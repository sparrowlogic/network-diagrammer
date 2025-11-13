package com.sparrowlogic.networkdiagram.service;

import com.sparrowlogic.networkdiagram.model.InfrastructureComponents;
import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.HashMap;

@Service
public class MermaidDiagramService {

    public String generateDiagram(InfrastructureComponents components) {
        // Find all external CIDR blocks that have access
        var externalCidrs = new java.util.HashSet<String>();
        components.securityGroups().forEach(sg -> 
            sg.rules().forEach(rule -> {
                if (!rule.source().startsWith("sg-") && 
                    ("0.0.0.0/0".equals(rule.source()) || "::/0".equals(rule.source()) || 
                     rule.source().contains("/32") || rule.source().contains("/128"))) {
                    externalCidrs.add(rule.source());
                }
            }));
        
        if (externalCidrs.isEmpty()) {
            return "No external CIDR exposures found.";
        }
        
        var diagrams = new StringBuilder();
        for (var cidr : externalCidrs) {
            diagrams.append("=== Attack Surface: ").append(cidr).append(" ===\n\n");
            diagrams.append(generateCidrDiagram(components, cidr));
            diagrams.append("\n\n");
        }
        return diagrams.toString();
    }
    
    private String generateCidrDiagram(InfrastructureComponents components, String focusCidr) {
        var diagram = new StringBuilder("graph TD\n");
        
        // Find security groups that allow access from this CIDR
        var exposedSgs = new java.util.HashSet<String>();
        var exposedPorts = new java.util.HashMap<String, java.util.List<String>>();
        
        components.securityGroups().forEach(sg -> {
            var ports = new java.util.ArrayList<String>();
            sg.rules().forEach(rule -> {
                if (focusCidr.equals(rule.source()) && "ingress".equals(rule.direction())) {
                    exposedSgs.add(sg.id());
                    ports.add("Port " + rule.fromPort() + "-" + rule.toPort() + " (" + rule.protocol() + ")");
                }
            });
            if (!ports.isEmpty()) {
                exposedPorts.put(sg.id(), ports);
            }
        });
        
        if (exposedSgs.isEmpty()) {
            return "graph TD\n    NoExposure[\"No exposure from " + focusCidr + "\"]\n";
        }
        
        // Add the CIDR block
        var cidrNode = "CIDR_" + focusCidr.replace(".", "_").replace("/", "_").replace(":", "_");
        diagram.append("    ").append(cidrNode).append("[\"").append(focusCidr).append("\"]\n");
        
        // Add exposed security groups
        exposedSgs.forEach(sgId -> {
            var sg = components.securityGroups().stream()
                .filter(s -> s.id().equals(sgId))
                .findFirst().orElse(null);
            if (sg != null) {
                var sgNode = sgId.replace("-", "_");
                diagram.append("    ").append(sgNode).append("[\"").append(sg.name()).append("\"]\n");
                
                // Add connections with port information
                exposedPorts.get(sgId).forEach(portInfo -> {
                    diagram.append("    ").append(cidrNode)
                           .append(" -->|\"").append(portInfo).append("\"|")
                           .append(sgNode).append("\n");
                });
            }
        });
        
        // Add ASGs and instances behind exposed security groups
        components.autoScalingGroups().stream()
            .filter(asg -> asg.securityGroups().stream().anyMatch(exposedSgs::contains))
            .forEach(asg -> {
                var asgNode = asg.name().replace("-", "_");
                diagram.append("    ").append(asgNode).append("[\"ASG: ").append(asg.name()).append("\"]\n");
                
                asg.securityGroups().stream()
                    .filter(exposedSgs::contains)
                    .forEach(sgId -> {
                        var sgNode = sgId.replace("-", "_");
                        diagram.append("    ").append(sgNode).append(" --> ").append(asgNode).append("\n");
                    });
            });
        
        // Add standalone instances behind exposed security groups
        var asgInstanceIds = components.autoScalingGroups().stream()
            .flatMap(asg -> asg.instanceIds().stream())
            .collect(java.util.stream.Collectors.toSet());
            
        components.instances().stream()
            .filter(i -> !asgInstanceIds.contains(i.id()))
            .filter(i -> i.securityGroups().stream().anyMatch(exposedSgs::contains))
            .forEach(instance -> {
                diagram.append("    ").append(instance.id())
                       .append("[\"").append(instance.id()).append(" (").append(instance.type()).append(")\"]\n");
                
                instance.securityGroups().stream()
                    .filter(exposedSgs::contains)
                    .forEach(sgId -> {
                        var sgNode = sgId.replace("-", "_");
                        diagram.append("    ").append(sgNode).append(" --> ").append(instance.id()).append("\n");
                    });
            });
        
        // Add colors
        diagram.append("\n    classDef cidr fill:#ff6666\n");
        diagram.append("    classDef sg fill:#99ccff\n");
        diagram.append("    classDef asg fill:#ffb3ff\n");
        diagram.append("    classDef ec2 fill:#ff9999\n\n");
        
        diagram.append("    class ").append(cidrNode).append(" cidr\n");
        exposedSgs.forEach(sgId -> 
            diagram.append("    class ").append(sgId.replace("-", "_")).append(" sg\n"));
        
        components.autoScalingGroups().stream()
            .filter(asg -> asg.securityGroups().stream().anyMatch(exposedSgs::contains))
            .forEach(asg -> 
                diagram.append("    class ").append(asg.name().replace("-", "_")).append(" asg\n"));
        
        components.instances().stream()
            .filter(i -> !asgInstanceIds.contains(i.id()))
            .filter(i -> i.securityGroups().stream().anyMatch(exposedSgs::contains))
            .forEach(instance -> 
                diagram.append("    class ").append(instance.id()).append(" ec2\n"));
        
        return diagram.toString();
    }
    
    private String generateSingleDiagram(InfrastructureComponents components, InfrastructureComponents.LoadBalancer focusLb) {
        var diagram = new StringBuilder("graph TD\n");
        
        // Find relevant components for this specific load balancer
        var relevantSgs = new java.util.HashSet<String>();
        var relevantInstances = new java.util.HashSet<String>();
        var relevantAsgs = new java.util.HashSet<String>();
        var relevantCidrs = new java.util.HashSet<String>();
        
        if (focusLb != null) {
            // Get instances that are actually targets of this specific load balancer
            var targetInstanceIds = new java.util.HashSet<String>();
            
            // For each target group of this load balancer, get the target instances
            // This is a simplified approach - in real implementation would call DescribeTargetHealth
            // For now, we'll use a heuristic based on load balancer name matching
            var lbNamePattern = focusLb.name().toLowerCase();
            
            // Find ASGs that might be associated with this load balancer (by naming convention)
            components.autoScalingGroups().stream()
                .filter(asg -> asg.name().toLowerCase().contains(lbNamePattern) || 
                              lbNamePattern.contains(asg.name().toLowerCase().split("-")[0]))
                .forEach(asg -> {
                    relevantAsgs.add(asg.name());
                    targetInstanceIds.addAll(asg.instanceIds());
                    relevantSgs.addAll(asg.securityGroups());
                });
            
            // Find instances that might be targets (by naming or tag convention)
            components.instances().stream()
                .filter(i -> !targetInstanceIds.contains(i.id())) // Not already in ASG
                .filter(i -> i.id().toLowerCase().contains(lbNamePattern.split("-")[0]))
                .forEach(i -> {
                    relevantInstances.add(i.id());
                    relevantSgs.addAll(i.securityGroups());
                });
            
            // If no specific matches found, fall back to port-based filtering
            if (relevantSgs.isEmpty()) {
                components.securityGroups().forEach(sg -> {
                    boolean isLbRelated = sg.rules().stream().anyMatch(rule -> 
                        "ingress".equals(rule.direction()) &&
                        ("0.0.0.0/0".equals(rule.source()) || "::/0".equals(rule.source())) &&
                        (rule.fromPort() == 80 || rule.fromPort() == 443 || rule.fromPort() == 8080)
                    );
                    
                    if (isLbRelated) {
                        relevantSgs.add(sg.id());
                    }
                });
            }
            
            // Add CIDRs from relevant security groups
            components.securityGroups().stream()
                .filter(sg -> relevantSgs.contains(sg.id()))
                .forEach(sg -> sg.rules().forEach(rule -> {
                    if (!rule.source().startsWith("sg-") && !isBroadSubnet(rule.source())) {
                        relevantCidrs.add(rule.source());
                    }
                }));
                
        } else {
            // For no focus, still filter out broad subnets
            components.securityGroups().forEach(sg -> {
                relevantSgs.add(sg.id());
                sg.rules().forEach(rule -> {
                    if (!rule.source().startsWith("sg-") && !isBroadSubnet(rule.source())) {
                        relevantCidrs.add(rule.source());
                    }
                });
            });
            components.autoScalingGroups().forEach(asg -> relevantAsgs.add(asg.name()));
            components.instances().forEach(i -> relevantInstances.add(i.id()));
        }
        
        // If no relevant components found, return minimal diagram
        if (relevantSgs.isEmpty() && relevantInstances.isEmpty() && relevantAsgs.isEmpty()) {
            if (focusLb != null) {
                var lbId = focusLb.id().substring(focusLb.id().lastIndexOf('/') + 1);
                diagram.append("    ").append(lbId)
                       .append("[\"").append(focusLb.name()).append(" (").append(focusLb.type()).append(")\"]\n");
                diagram.append("    classDef lb fill:#99ff99\n");
                diagram.append("    class ").append(lbId).append(" lb\n");
            }
            return diagram.toString();
        }
        
        // Separate external and other CIDRs
        var externalCidrs = new java.util.HashSet<String>();
        var otherCidrs = new java.util.HashSet<String>();
        
        relevantCidrs.forEach(cidr -> {
            if (cidr.equals("0.0.0.0/0") || cidr.equals("::/0")) {
                externalCidrs.add(cidr);
            } else {
                otherCidrs.add(cidr);
            }
        });
        
        // Add external CIDR blocks first
        if (!externalCidrs.isEmpty()) {
            diagram.append("    subgraph External[\"External Networks\"]\n");
            externalCidrs.forEach(cidr -> {
                var cidrNode = "CIDR_" + cidr.replace(".", "_").replace("/", "_").replace(":", "_");
                diagram.append("        ").append(cidrNode)
                       .append("[\"").append(cidr).append("\"]\n");
            });
            diagram.append("    end\n\n");
        }
        
        // Add other specific CIDR blocks
        otherCidrs.forEach(cidr -> {
            var cidrNode = "CIDR_" + cidr.replace(".", "_").replace("/", "_").replace(":", "_");
            diagram.append("    ").append(cidrNode)
                   .append("[\"").append(cidr).append("\"]\n");
        });
        
        // Add focused load balancer
        if (focusLb != null) {
            var lbId = focusLb.id().substring(focusLb.id().lastIndexOf('/') + 1);
            diagram.append("    ").append(lbId)
                   .append("[\"").append(focusLb.name()).append(" (").append(focusLb.type()).append(")\"]\n");
        }
        
        // Add only relevant security groups
        components.securityGroups().stream()
            .filter(sg -> relevantSgs.contains(sg.id()))
            .forEach(sg -> {
                var sgNode = sg.id().replace("-", "_");
                diagram.append("    ").append(sgNode)
                       .append("[\"").append(sg.name()).append("\"]\n");
            });
        
        // Add relevant ASGs
        components.autoScalingGroups().stream()
            .filter(asg -> relevantAsgs.contains(asg.name()))
            .forEach(asg -> 
                diagram.append("    ").append(asg.name().replace("-", "_"))
                       .append("[\"ASG: ").append(asg.name()).append("\"]\n"));
        
        // Add only standalone instances (not in ASGs)
        components.instances().stream()
            .filter(instance -> relevantInstances.contains(instance.id()))
            .forEach(instance -> 
                diagram.append("    ").append(instance.id())
                       .append("[\"").append(instance.id()).append(" (").append(instance.type()).append(")\"]\n"));
        
        // Add connections from external to load balancer
        if (focusLb != null && !externalCidrs.isEmpty()) {
            var lbId = focusLb.id().substring(focusLb.id().lastIndexOf('/') + 1);
            externalCidrs.forEach(cidr -> {
                var cidrNode = "CIDR_" + cidr.replace(".", "_").replace("/", "_").replace(":", "_");
                diagram.append("    ").append(cidrNode)
                       .append(" -->|\"HTTP/HTTPS\"|").append(lbId).append("\n");
            });
        }
        
        // Add only relevant security group connections
        components.securityGroups().stream()
            .filter(sg -> relevantSgs.contains(sg.id()))
            .forEach(sg -> {
                var sgNode = sg.id().replace("-", "_");
                
                // Group rules by direction and create connections for each unique source/destination
                sg.rules().forEach(rule -> {
                    // Skip broad subnets
                    if (!rule.source().startsWith("sg-") && isBroadSubnet(rule.source())) {
                        return;
                    }
                    
                    var label = rule.direction().toUpperCase() + " Port " + rule.fromPort() + 
                               "-" + rule.toPort() + " (" + rule.protocol() + ")";
                    
                    if (rule.source().startsWith("sg-") && relevantSgs.contains(rule.source())) {
                        // Security group to security group connection
                        var otherSg = rule.source().replace("-", "_");
                        if ("ingress".equals(rule.direction())) {
                            diagram.append("    ").append(otherSg)
                                   .append(" -->|\"").append(label).append("\"|")
                                   .append(sgNode).append("\n");
                        } else {
                            diagram.append("    ").append(sgNode)
                                   .append(" -->|\"").append(label).append("\"|")
                                   .append(otherSg).append("\n");
                        }
                    } else if (!rule.source().startsWith("sg-") && relevantCidrs.contains(rule.source())) {
                        // CIDR to security group connection
                        var cidrNode = "CIDR_" + rule.source().replace(".", "_").replace("/", "_").replace(":", "_");
                        if ("ingress".equals(rule.direction())) {
                            diagram.append("    ").append(cidrNode)
                                   .append(" -->|\"").append(label).append("\"|")
                                   .append(sgNode).append("\n");
                        } else {
                            diagram.append("    ").append(sgNode)
                                   .append(" -->|\"").append(label).append("\"|")
                                   .append(cidrNode).append("\n");
                        }
                    }
                });
                
                // Connect security groups to ASGs and standalone instances
                components.autoScalingGroups().stream()
                    .filter(asg -> relevantAsgs.contains(asg.name()) && asg.securityGroups().contains(sg.id()))
                    .forEach(asg -> diagram.append("    ").append(sgNode)
                                           .append(" --> ").append(asg.name().replace("-", "_")).append("\n"));
                
                components.instances().stream()
                    .filter(i -> relevantInstances.contains(i.id()) && i.securityGroups().contains(sg.id()))
                    .forEach(i -> diagram.append("    ").append(sgNode)
                                         .append(" --> ").append(i.id()).append("\n"));
            });
        
        // Add color classes
        diagram.append("\n    classDef ec2 fill:#ff9999\n");
        diagram.append("    classDef sg fill:#99ccff\n");
        diagram.append("    classDef lb fill:#99ff99\n");
        diagram.append("    classDef cidr fill:#ffcc99\n");
        diagram.append("    classDef asg fill:#ffb3ff\n\n");
        
        // Apply colors to relevant components only
        components.instances().stream()
            .filter(instance -> relevantInstances.contains(instance.id()))
            .forEach(instance -> 
                diagram.append("    class ").append(instance.id()).append(" ec2\n"));
        
        components.autoScalingGroups().stream()
            .filter(asg -> relevantAsgs.contains(asg.name()))
            .forEach(asg -> 
                diagram.append("    class ").append(asg.name().replace("-", "_")).append(" asg\n"));
        
        components.securityGroups().stream()
            .filter(sg -> relevantSgs.contains(sg.id()))
            .forEach(sg -> 
                diagram.append("    class ").append(sg.id().replace("-", "_")).append(" sg\n"));
        
        if (focusLb != null) {
            var lbId = focusLb.id().substring(focusLb.id().lastIndexOf('/') + 1);
            diagram.append("    class ").append(lbId).append(" lb\n");
        }
        
        relevantCidrs.forEach(cidr -> {
            var sourceNode = "CIDR_" + cidr.replace(".", "_").replace("/", "_").replace(":", "_");
            diagram.append("    class ").append(sourceNode).append(" cidr\n");
        });
        
        return diagram.toString();
    }
    
    private boolean isBroadSubnet(String cidr) {
        if (!cidr.contains("/")) return false;
        try {
            int prefix = Integer.parseInt(cidr.substring(cidr.indexOf('/') + 1));
            // Consider /16 or larger (smaller prefix) as broad subnets
            return prefix <= 16;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
