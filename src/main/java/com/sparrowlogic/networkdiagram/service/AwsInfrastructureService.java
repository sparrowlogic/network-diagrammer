package com.sparrowlogic.networkdiagram.service;

import com.sparrowlogic.networkdiagram.model.InfrastructureComponents;
import com.sparrowlogic.networkdiagram.model.SecurityGroupRule;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.services.autoscaling.AutoScalingClient;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client;

import java.util.List;

@Service
public class AwsInfrastructureService {

    public InfrastructureComponents getInfrastructure(String profile, String region, String vpcId) {
        var credentialsProvider = profile != null ? 
            ProfileCredentialsProvider.create(profile) : 
            ProfileCredentialsProvider.create();
            
        var ec2Client = Ec2Client.builder()
            .credentialsProvider(credentialsProvider)
            .region(software.amazon.awssdk.regions.Region.of(region))
            .build();
        var elbClient = ElasticLoadBalancingV2Client.builder()
            .credentialsProvider(credentialsProvider)
            .region(software.amazon.awssdk.regions.Region.of(region))
            .build();

        var asgClient = AutoScalingClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(software.amazon.awssdk.regions.Region.of(region))
            .build();

        var sgFilter = vpcId != null ? 
            DescribeSecurityGroupsRequest.builder().filters(Filter.builder().name("vpc-id").values(vpcId).build()).build() :
            DescribeSecurityGroupsRequest.builder().build();

        var securityGroups = ec2Client.describeSecurityGroups(sgFilter).securityGroups().stream()
            .map(sg -> {
                var allRules = new java.util.ArrayList<SecurityGroupRule>();
                
                // Process ingress rules - handle multiple sources per rule
                sg.ipPermissions().forEach(rule -> {
                    // Handle CIDR blocks
                    rule.ipRanges().forEach(ipRange -> {
                        allRules.add(new SecurityGroupRule(
                            rule.ipProtocol(),
                            rule.fromPort() != null ? rule.fromPort() : 0,
                            rule.toPort() != null ? rule.toPort() : 0,
                            ipRange.cidrIp(),
                            "ingress"
                        ));
                    });
                    
                    // Handle security group references
                    rule.userIdGroupPairs().forEach(sgPair -> {
                        allRules.add(new SecurityGroupRule(
                            rule.ipProtocol(),
                            rule.fromPort() != null ? rule.fromPort() : 0,
                            rule.toPort() != null ? rule.toPort() : 0,
                            sgPair.groupId(),
                            "ingress"
                        ));
                    });
                });
                
                // Process egress rules - handle multiple destinations per rule
                sg.ipPermissionsEgress().forEach(rule -> {
                    // Handle CIDR blocks
                    rule.ipRanges().forEach(ipRange -> {
                        allRules.add(new SecurityGroupRule(
                            rule.ipProtocol(),
                            rule.fromPort() != null ? rule.fromPort() : 0,
                            rule.toPort() != null ? rule.toPort() : 0,
                            ipRange.cidrIp(),
                            "egress"
                        ));
                    });
                    
                    // Handle security group references
                    rule.userIdGroupPairs().forEach(sgPair -> {
                        allRules.add(new SecurityGroupRule(
                            rule.ipProtocol(),
                            rule.fromPort() != null ? rule.fromPort() : 0,
                            rule.toPort() != null ? rule.toPort() : 0,
                            sgPair.groupId(),
                            "egress"
                        ));
                    });
                });
                
                return new InfrastructureComponents.SecurityGroup(sg.groupId(), sg.groupName(), allRules);
            }).toList();

        var loadBalancers = elbClient.describeLoadBalancers().loadBalancers().stream()
            .filter(lb -> vpcId == null || lb.vpcId().equals(vpcId))
            .map(lb -> {
                // Get target groups for this load balancer
                var targetGroups = elbClient.describeTargetGroups(
                    software.amazon.awssdk.services.elasticloadbalancingv2.model.DescribeTargetGroupsRequest.builder()
                        .loadBalancerArn(lb.loadBalancerArn())
                        .build()
                ).targetGroups().stream().map(tg -> tg.targetGroupArn()).toList();
                
                return new InfrastructureComponents.LoadBalancer(
                    lb.loadBalancerArn(),
                    lb.loadBalancerName(),
                    lb.type().toString(),
                    targetGroups
                );
            }).toList();

        var instanceFilter = vpcId != null ?
            DescribeInstancesRequest.builder().filters(Filter.builder().name("vpc-id").values(vpcId).build()).build() :
            DescribeInstancesRequest.builder().build();

        var instances = ec2Client.describeInstances(instanceFilter).reservations().stream()
            .flatMap(r -> r.instances().stream())
            .map(i -> new InfrastructureComponents.Instance(
                i.instanceId(),
                i.instanceType().toString(),
                i.securityGroups().stream().map(sg -> sg.groupId()).toList()
            )).toList();

        // Fetch Auto Scaling Groups
        var autoScalingGroups = asgClient.describeAutoScalingGroups().autoScalingGroups().stream()
            .map(asg -> {
                var instanceIds = asg.instances().stream().map(i -> i.instanceId()).toList();
                // Get security groups from instances in this ASG
                var asgSecurityGroups = instances.stream()
                    .filter(i -> instanceIds.contains(i.id()))
                    .flatMap(i -> i.securityGroups().stream())
                    .distinct()
                    .toList();
                return new InfrastructureComponents.AutoScalingGroup(
                    asg.autoScalingGroupName(),
                    instanceIds,
                    asgSecurityGroups
                );
            }).toList();

        return new InfrastructureComponents(securityGroups, loadBalancers, instances, autoScalingGroups, vpcId, List.of());
    }
}
