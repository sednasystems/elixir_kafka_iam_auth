defmodule ElixirKafkaIamAuth do
  @moduledoc """
  SASL AWS_MSK_IAM auth backend implementation for brod Erlang library.
  To authenticate, supply aws_secret_key_id and aws_secret_access_key with access to MSK cluster
  """
  @behaviour :kpro_auth_backend
  require Logger

  @kpro_lib Application.compile_env(:elixir_kafka_iam_auth, :kpro_lib, KafkaProtocolLib)
  # @signed_payload_generator Application.compile_env(
  #                             :elixir_kafka_iam_auth,
  #                             :signed_payload_generator,
  #                             SignedPayloadGenerator
  #                           )

  @handshake_version 1

  def auth(
        host,
        sock,
        mod,
        client_id,
        timeout,
        _sasl_opts = {mechanism = :AWS_MSK_IAM, :ecs_role_auth}
      ) do
    # This will, maybe surprisingly, send a request to the metadata endpoint for the container, it relies on AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
    # being set
    %{
      access_key_id: access_key_id,
      secret_access_key: secret_access_key,
      security_token: security_token
    } = ExAws.Config.new(:ecs)

    Logger.debug(
      "Obtained access_key_id: #{access_key_id} and secret_access_key #{secret_access_key}"
    )

    auth(
      host,
      sock,
      mod,
      client_id,
      timeout,
      {mechanism, access_key_id, secret_access_key, security_token}
    )
  end

  def auth(
        _host,
        _sock,
        _mod,
        _client_id,
        _timeout,
        _sasl_opts =
          {_mechanism = :AWS_MSK_IAM, aws_secret_key_id, _aws_secret_access_key}
      )
      when aws_secret_key_id == nil,
      do: {:error, "AWS Secret Key ID is empty"}

  def auth(
        _host,
        _sock,
        _mod,
        _client_id,
        _timeout,
        _sasl_opts =
          {_mechanism = :AWS_MSK_IAM, _aws_secret_key_id, aws_secret_access_key}
      )
      when aws_secret_access_key == nil,
      do: {:error, "AWS Secret Access Key is empty"}

  # The following code is based on the implmentation of SASL handshake implementation from kafka_protocol Erlang library
  # Ref: https://github.com/kafka4beam/kafka_protocol/blob/master/src/kpro_sasl.erl
  @impl true
  @spec auth(
          any(),
          port(),
          :gen_tcp | :ssl,
          binary(),
          :infinity | non_neg_integer(),
          {:AWS_MSK_IAM, binary(), binary()}
        ) ::
          :ok | {:error, any()}
  def auth(
        host,
        sock,
        mod,
        client_id,
        timeout,
        _sasl_opts =
          {_mechanism = :AWS_MSK_IAM, aws_secret_key_id, aws_secret_access_key, security_token}
      )
      when is_binary(aws_secret_key_id) and is_binary(aws_secret_access_key) do
    with :ok <- handshake(sock, mod, timeout, client_id, :OAUTHBEARER, @handshake_version) do
      region = Application.get_env(:elixir_kafka_iam_auth, :aws_region)
      service = Application.get_env(:elixir_kafka_iam_auth, :kafka_service)

      Logger.debug("Connecting to kafka with region #{region} and service #{service}")

      Logger.debug(
        "Params: #{inspect(%{host: host, sock: sock, mod: mod, client_id: client_id, timeout: timeout, sasl_opts: {:AWS_MSK_IAM, aws_secret_key_id, aws_secret_access_key}})}"
      )

      # client_final_msg =
      #   @signed_payload_generator.get_msk_signed_payload(
      #     host,
      #     DateTime.utc_now(),
      #     aws_secret_key_id,
      #     aws_secret_access_key,
      #     region,
      #     service
      #   )
      #

      action_query_param = URI.encode_query(%{"Action" => "kafka-cluster:Connect"})
      url = "https://kafka.#{region}.amazonaws.com?#{action_query_param}"

      token =
        :aws_signature.sign_v4_query_params(
          aws_secret_key_id,
          aws_secret_access_key,
          "us-west-2",
          "kafka-cluster",
          DateTime.utc_now() |> NaiveDateTime.to_erl(),
          "GET",
          url,
          ttl: 900,
          # Note the underlying library does assign this to the X-Aws-Security-Token header and amz regards it as it
          # not sure why in other places they call it the session token
          session_token: URI.encode_www_form(security_token)
        )
        |> URI.parse()
        |> (fn u ->
              Map.put(
                u,
                :query,
                u.query
                |> URI.decode_query()
                |> Map.put("User-Agent", "sedna-msk-iam-client")
                |> URI.encode_query(:rfc3986)
              )
              |> Map.put(:path, "/")
            end).()
        |> URI.to_string()
        |> Base.url_encode64()
        |> String.replace(~r/=/, "", global: true)

      # %{token: token} =
      # client_final_msg =
      #   %{
      #     token:
      #       "aHR0cHM6Ly9rYWZrYS51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS8_QWN0aW9uPWthZmthLWNsdXN0ZXIlM0FDb25uZWN0JlVzZXItQWdlbnQ9YXdzLW1zay1pYW0tc2FzbC1zaWduZXItanMlMkYxLjAuMCZYLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFTSUE2TEVCWUFHREJBTzQ1NlY2JTJGMjAyNDA5MDMlMkZ1cy13ZXN0LTIlMkZrYWZrYS1jbHVzdGVyJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNDA5MDNUMTUyMzE3WiZYLUFtei1FeHBpcmVzPTkwMCZYLUFtei1TZWN1cml0eS1Ub2tlbj1JUW9KYjNKcFoybHVYMlZqRUtMJTJGJTJGJTJGJTJGJTJGJTJGJTJGJTJGJTJGJTJGd0VhQ1dWMUxYZGxjM1F0TVNKSE1FVUNJUUNLNFpUZSUyRnpPdE9rSlp6VklLcFQzNkRQczE4MjY2MWVTcHdkTWQ5S0Y4ZlFJZ1hiUXVtRVYwJTJGbFBHdm5KSk43UDQwckQzTnNEd2luTmZqQmNhNnRCYmdWb3FrZ01JdSUyRiUyRiUyRiUyRiUyRiUyRiUyRiUyRiUyRiUyRiUyRkFSQUFHZ3c1T0RVNU5qY3hNREF5T1RRaURQTzJraDElMkIxb3ByMXVYejJ5cm1BdnFzeDB0ZHJmU0lWZlNBSmlNTjYlMkYlMkYlMkZIWWt0bGwzZkZENWpJNzBkbnBIa1h6NUdBcDl1UGVUazlWalBUcnlzZ25UMmslMkJERHluY1FUaW45VXE0JTJGa3R3bGdrZXFCWEhMSUl4V2txYzlzeDlZVHNmeW93MmxZMDZUNGJMRFR3R0c4SUdjQjh5aHU1JTJGRWV6SXBjVHZiR3psaDlTWnN2Qk9uRjRpNWN5WXZjR0w2V1JWaUR0bUtZVjFPTWY3R212RGw3WDJ3TVVaQkZyck9SMTAlMkZNTlpBMkdYUk5QWnZhaHhjVU1HSkJFT2RvSElUMjhscVAzQUNHSk1IVml6YnRJQUJsNlZ0dVNTSGpxQjdsakdrYjMlMkYxdHhvSDN0OXBLMkhMWSUyRjh5cHBHcnpQbk1hSktHbWI2NiUyQjJOZ3YyQ25LRHFFYVdmc29xejdma3ZrUEhIVTFqVkNPVldvcDRvOFd0bjQlMkZrTTJIRWV4SnUlMkZ3dDMlMkZLRU8xRk4lMkJ6TE1Fd2hkbUExSUc1eDlmU2R2SXhDMUtFcFA0NCUyQnNLUWVpTHRKamlnZWFxMzdpTmVCenZDVCUyRmkxbGZnenZyYTRYQmJnNDFUdk5CUTNSTFloVEZDQW41bVklMkJlOHVXZzQ5QTdla3o5aEF3eGJUYnRnWTZwZ0ZCclMlMkJ3YmNQN0dpcjNhQ3psTUpKVE5vUWRlckY2dzJ2bGFYRER2SzhOTkVDS3BvZ3VKVGFPY2RzTXlkWkdVVlpTQ0lOU1NFUWJ1dTNnUEhweFdsYmVqN01RRVVzbGFLM0s4cmpnWSUyRkFJSFZmU1FPTTlsWiUyRkQlMkJVaTc5bTIzdlNIQkxpY240bENucUFrempYWkhLJTJGeEJZem5iJTJGMnBSNzk0R1B3SVZUdW1OSHFmYldMWVpxeTRZaXV4SFNGbk1NTDVLZWNmelI5ZVluNDM5VXUlMkJSRCUyRnhQYUJmSVRzelkmWC1BbXotU2lnbmF0dXJlPWE1ZDFiMjhlYWMzY2RmNzI5ZWQzODczMDI3MTYxZWNjMTE4ZGZmMWI2NjI0YzY2Y2FkN2Q5YjQxNWQxN2Y1MzImWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0",
      #     expiryTime: 1_725_377_897_000
      #   }
      #   |> Jason.encode!()

      # client_final_msg = token
      #

      client_final_msg =
        "n,,#{<<1>>}auth=Bearer #{token}#{<<1>>}#{<<1>>}"
        |> :binary.bin_to_list()

      Logger.debug("Generated client final msg #{inspect(client_final_msg)}")

      server_final_msg = send_recv(sock, mod, client_id, timeout, client_final_msg)

      Logger.debug("server_final_msg #{inspect(server_final_msg)}")

      case @kpro_lib.find(:error_code, server_final_msg) do
        :no_error -> :ok
        other -> {:error, other}
      end
    else
      error ->
        Logger.error("Handshake failed #{error}")
        {:error, error}
    end
  end

  def auth(_host, _sock, _mod, _client_id, _timeout, _sasl_opts) do
    {:error, "Invalid SASL mechanism"}
  end

  defp send_recv(sock, mod, client_id, timeout, payload) do
    req = @kpro_lib.make(:sasl_authenticate, _auth_req_vsn = 0, [{:auth_bytes, payload}])
    rsp = @kpro_lib.send_and_recv(req, sock, mod, client_id, timeout)

    Logger.debug("Sending auth request: #{inspect(req)}")
    Logger.debug("Final Auth Response from server - #{inspect(rsp)}")

    rsp
  end

  defp cs([]), do: "[]"
  defp cs([x]), do: x
  defp cs([h | t]), do: [h, "," | cs(t)]

  defp handshake(sock, mod, timeout, client_id, mechanism, vsn) do
    req = @kpro_lib.make(:sasl_handshake, vsn, [{:mechanism, mechanism}])
    rsp = @kpro_lib.send_and_recv(req, sock, mod, client_id, timeout)
    error_code = @kpro_lib.find(:error_code, rsp)

    Logger.debug("Error Code field in initial handshake response : #{error_code}")

    case error_code do
      :no_error ->
        :ok

      :unsupported_sasl_mechanism ->
        enabled_mechanisms = @kpro_lib.find(:mechanisms, rsp)
        "sasl mechanism #{mechanism} is not enabled in kafka, "
        "enabled mechanism(s): #{cs(enabled_mechanisms)}"

      other ->
        other
    end
  end

  # def connect_to_sedna_kafka() do
  #   :brod.get_metadata(
  #     [{"b-1.cdcv3.0d5r8k.c12.kafka.us-west-2.amazonaws.com", 9098}],
  #     ["sedna_test3_message"],
  #     ssl: true,
  #     sasl: {
  #       :callback,
  #       ElixirKafkaIamAuth,
  #       {:AWS_MSK_IAM, System.get_env("AWS_ACCESS_KEY_ID"),
  #        System.get_env("AWS_SECRET_ACCESS_KEY")}
  #     }
  #   )
  # end
  #
  #

  # The implementation of auth/7 was missing in the orig. version - it just adds the handshake version
  # which we will ignore here
  @impl true
  def auth(host, sock, _handshake_version, mod, client_name, timeout, saslopts) do
    auth(host, sock, mod, client_name, timeout, saslopts)
  end
end
