package com.sparrowlogic.networkdiagram.service;

import com.sparrowlogic.networkdiagram.model.InfrastructureComponents;
import com.sparrowlogic.networkdiagram.model.SecurityGroupRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MermaidDiagramServiceTest {

    private final MermaidDiagramService service = new MermaidDiagramService();

    @Test
    void shouldGenerateDiagramWithSecurityGroups() {
        var rule = new SecurityGroupRule("tcp", 80, 80, "0.0.0.0/0", "ingress");
        var sg = new InfrastructureComponents.SecurityGroup("sg-123", "web-sg", List.of(rule));
        var instance = new InfrastructureComponents.Instance("i-123", "t2.micro", List.of("sg-123"));
        var components = new InfrastructureComponents(List.of(sg), List.of(), List.of(instance), List.of(), "vpc-123", List.of());

        var diagram = service.generateDiagram(components);

        assertTrue(diagram.contains("graph TD"));
        assertFalse(diagram.isEmpty());
    }

    @Test
    void shouldGenerateDiagramWithLoadBalancers() {
        var lb = new InfrastructureComponents.LoadBalancer("arn:aws:elasticloadbalancing::loadbalancer/app/test-lb", "test-lb", "application", List.of());
        var components = new InfrastructureComponents(List.of(), List.of(lb), List.of(), List.of(), "vpc-123", List.of());

        var diagram = service.generateDiagram(components);

        assertTrue(diagram.contains("No external CIDR exposures found"));
    }
}
