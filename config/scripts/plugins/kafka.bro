@load Apache/Kafka
## Setup Kafka output
redef Kafka::topic_name = "bro-raw";
redef Kafka::tag_json = F;
redef Log::default_writer = Log::WRITER_KAFKAWRITER;
