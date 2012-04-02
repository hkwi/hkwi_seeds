#!/bin/env python
# NOTE: For Python 2.x
import pika

import optparse
ps = optparse.OptionParser()
ps.add_option("-s", "--server", dest="host", default="localhost")
ps.add_option("-u", "--username", dest="username", default="guest")
ps.add_option("-w", "--password", dest="password", default="guest")
(opts, args) = ps.parse_args()

connection = pika.BlockingConnection(pika.ConnectionParameters(host=opts.host,
  credentials=pika.PlainCredentials(opts.username, opts.password)))

channel=connection.channel()
queue_name = channel.queue_declare(exclusive=True).method.queue
channel.queue_bind(exchange="amq.rabbitmq.trace", queue=queue_name, routing_key="#")
def cb(ch, method, properties, body):
  print ch, method, properties, body

channel.basic_consume(cb, queue=queue_name, no_ack=True)
channel.start_consuming()
