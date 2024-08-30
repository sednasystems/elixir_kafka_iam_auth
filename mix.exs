defmodule ElixirKafkaIamAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixir_kafka_iam_auth,
      version: "0.1.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:broadway_kafka, "~> 0.4.1"},
      {:aws_signature, "~> 0.3.0"},
      {:jason, "~> 1.3"},
      {:hammox, "~> 0.5", only: :test},
      {:ex_aws, "~> 2.5"},
      {:hackney, "~> 1.9"}
    ]
  end
end
