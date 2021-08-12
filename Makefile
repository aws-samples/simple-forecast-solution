#
# ...
#
# Created:
#   Sat Jul 24 14:45:13 UTC 2021
#
# Usage:
#   make deploy EMAIL=<your@email.address> INSTANCE_TYPE=<ml.* ec2 instance type>
# 
export SHELL
SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# SNS emails will be sent to this address to notify when the SageMaker Notebook
# instances are deployed and when the ML forecasting jobs are completed.
EMAIL:=
INSTANCE_TYPE:=ml.t2.medium

.PHONY: ./cdk/bootstrap.py

# Deploy the SFS stack
deploy: AfaStack

destroy:
	cd cdk ; cdk destroy --all

# Generate the bootstrap cloudformation YAML template
template.yaml: ./cdk/bootstrap.py
	( cd cdk ; cdk synth AfaBootstrapStack ) > $@

AfaStack:
	cd cdk ; \
		cdk deploy $@ --parameters $@:emailAddress=${EMAIL} \
		--parameters $@:instanceType=${INSTANCE_TYPE}

AfaBootstrapStack:
	cd cdk ; \
		cdk deploy $@ --parameters $@:emailAddress=${EMAIL}
