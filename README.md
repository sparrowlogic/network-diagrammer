# Network Diagram Generator

A Spring Boot application that generates Mermaid network diagrams from AWS infrastructure components.

## Features

- Discovers AWS infrastructure (EC2, ELB, Auto Scaling Groups, Security Groups)
- Generates Mermaid diagrams showing network topology and security group relationships
- Supports filtering by VPC ID
- REST API for programmatic access

## Prerequisites

- Java 25
- Maven 3.6+
- AWS CLI configured with appropriate credentials

## IAM Permissions Required

The application requires the following AWS IAM permissions to discover and analyze your infrastructure:

### EC2 Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeNetworkInterfaces"
            ],
            "Resource": "*"
        }
    ]
}
```

### Elastic Load Balancing Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeListeners"
            ],
            "Resource": "*"
        }
    ]
}
```

### Auto Scaling Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "autoscaling:DescribeAutoScalingGroups"
            ],
            "Resource": "*"
        }
    ]
}
```

### Complete IAM Policy
For convenience, here's a complete IAM policy with all required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeNetworkInterfaces",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeListeners",
                "autoscaling:DescribeAutoScalingGroups"
            ],
            "Resource": "*"
        }
    ]
}
```

## Setup

1. Clone the repository
2. Configure AWS credentials using one of these methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
   - AWS profiles in `~/.aws/credentials`

3. Build the application:
   ```bash
   ./mvnw clean package
   ```

4. Run the application:
   ```bash
   ./mvnw spring-boot:run
   ```

## Usage

The application exposes REST endpoints to generate network diagrams. Access the API at `http://localhost:8080`.

### Query Parameters
- `profile`: AWS profile name (optional)
- `region`: AWS region (required)
- `vpcId`: VPC ID to filter resources (optional)

## Security Considerations

- Use least privilege IAM policies
- Consider using IAM roles instead of access keys when running on EC2
- Regularly rotate access keys if using programmatic access
- Monitor CloudTrail logs for API usage
