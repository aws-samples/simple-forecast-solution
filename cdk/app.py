#!/usr/bin/env python3
import os
import sys

import aws_cdk as core

from cdk.stack import AfaStack
from cdk.bootstrap import BootstrapStack

PWD = os.path.dirname(os.path.realpath(__file__))

TAG_NAME = "Project"
TAG_VALUE = "Afa"

app = core.App()

stack_name = app.node.try_get_context("afa_stack_name")
boot_stack_name = app.node.try_get_context("boot_stack_name")
branch = app.node.try_get_context("branch")
project_tag = app.node.try_get_context("project_tag")

if stack_name is None:
    stack_name = "AfaStack"

if boot_stack_name is None:
    boot_stack_name = "AfaBootstrapStack"

if branch is None:
    branch = "main"

if project_tag is None:
    project_tag = TAG_VALUE

core.Tags.of(app).add(TAG_NAME, project_tag)

AfaStack(app, stack_name)
BootstrapStack(app, boot_stack_name, lambdamap_branch=branch,
                afa_branch=branch)

app.synth()