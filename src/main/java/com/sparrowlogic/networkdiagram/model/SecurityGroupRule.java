package com.sparrowlogic.networkdiagram.model;

public record SecurityGroupRule(
    String protocol,
    int fromPort,
    int toPort,
    String source,
    String direction
) {}
