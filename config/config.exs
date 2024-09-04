import Config

config :elixir_kafka_iam_auth,
  kafka_service: "kafka-service",
  aws_region: "us-west-2"

import_config "#{Mix.env()}.exs"
