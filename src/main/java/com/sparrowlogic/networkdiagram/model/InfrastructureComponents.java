package com.sparrowlogic.networkdiagram.model;

import java.util.List;

public record InfrastructureComponents(
    List<SecurityGroup> securityGroups,
    List<LoadBalancer> loadBalancers,
    List<Instance> instances,
    List<AutoScalingGroup> autoScalingGroups,
    String vpcId,
    List<String> subnetIds
) {
    public record SecurityGroup(String id, String name, List<SecurityGroupRule> rules) {}
    public record LoadBalancer(String id, String name, String type, List<String> targetGroups) {}
    public record Instance(String id, String type, List<String> securityGroups) {}
    public record AutoScalingGroup(String name, List<String> instanceIds, List<String> securityGroups) {}
}
