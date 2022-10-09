#
# Usage:
#   make deploy EMAIL=<your email address> INSTANCE_TYPE=<ml.* ec2 instance type>
# 
export SHELL
SHELL:=/bin/bash
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

STACK_NAME:=AfaBootstrapStack

# SNS emails will be sent to this address to notify when the SageMaker Notebook
# instances are deployed and when the ML forecasting jobs are completed.
EMAIL:=user@example.com
INSTANCE_TYPE:=ml.t2.medium

.PHONY: deploy destroy

# create the virtual environment from which to run each target
.venv: requirements.txt
	python3 -B -m venv $@
	source $@/bin/activate ; pip install -r $<

destroy:
	cd cdk ; cdk destroy --all

# Generate the cloudformation YAML template
template.yaml: cdk/bootstrap.py .venv
	source $(word 2, $^)/bin/activate ; \
	cdk synth -a 'python3 -B $<' > $@

${STACK_NAME}: template.yaml .venv
	source $(word 2, $^)/bin/activate ; \
	aws cloudformation deploy \
		--template-file $< \
		--capabilities CAPABILITY_NAMED_IAM \
		--stack-name $@ \
		--parameter-overrides \
			emailAddress=${EMAIL} \
			instanceType=${INSTANCE_TYPE}

deploy: ${STACK_NAME}

deploy-cdk:
	cdk deploy -a 'python -B app.py' ${STACK_NAME}