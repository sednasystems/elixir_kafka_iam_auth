import Config

config :elixir_kafka_iam_auth,
  kpro_lib: KafkaProtocolLibMock,
  signed_payload_generator: SignedPayloadGeneratorMock,
  aws_region: "us-east-2",
  kafka_service: "kafka-cluster"
