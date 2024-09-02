defmodule ElixirKafkaIamAuth do
  @moduledoc """
  SASL AWS_MSK_IAM auth backend implementation for brod Erlang library.
  To authenticate, supply aws_secret_key_id and aws_secret_access_key with access to MSK cluster
  """
  @behaviour :kpro_auth_backend
  require Logger

  @kpro_lib Application.compile_env(:elixir_kafka_iam_auth, :kpro_lib, KafkaProtocolLib)
  @signed_payload_generator Application.compile_env(
                              :elixir_kafka_iam_auth,
                              :signed_payload_generator,
                              SignedPayloadGenerator
                            )

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
    %{access_key_id: access_key_id, secret_access_key: secret_access_key} = ExAws.Config.new(:ecs)

    Logger.debug(
      "Obtained access_key_id: #{access_key_id} and secret_access_key #{secret_access_key}"
    )

    auth(host, sock, mod, client_id, timeout, {mechanism, access_key_id, secret_access_key})
  end

  def auth(
        _host,
        _sock,
        _mod,
        _client_id,
        _timeout,
        _sasl_opts = {_mechanism = :AWS_MSK_IAM, aws_secret_key_id, _aws_secret_access_key}
      )
      when aws_secret_key_id == nil,
      do: {:error, "AWS Secret Key ID is empty"}

  def auth(
        _host,
        _sock,
        _mod,
        _client_id,
        _timeout,
        _sasl_opts = {_mechanism = :AWS_MSK_IAM, _aws_secret_key_id, aws_secret_access_key}
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
        _sasl_opts = {mechanism = :AWS_MSK_IAM, aws_secret_key_id, aws_secret_access_key}
      )
      when is_binary(aws_secret_key_id) and is_binary(aws_secret_access_key) do
    with :ok <- handshake(sock, mod, timeout, client_id, mechanism, @handshake_version) do
      region = Application.get_env(:elixir_kafka_iam_auth, :aws_region)
      service = Application.get_env(:elixir_kafka_iam_auth, :kafka_service)

      Logger.debug("Connecting to kafka with region #{region} and service #{service}")

      Logger.debug(
        "Params: #{inspect(%{host: host, sock: sock, mod: mod, client_id: client_id, timeout: timeout, sasl_opts: {:AWS_MSK_IAM, aws_secret_key_id, aws_secret_access_key}})}"
      )

      client_final_msg =
        @signed_payload_generator.get_msk_signed_payload(
          host,
          DateTime.utc_now(),
          aws_secret_key_id,
          aws_secret_access_key,
          region,
          service
        )

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
end
