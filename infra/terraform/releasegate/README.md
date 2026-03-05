# ReleaseGate Terraform Module

This module provisions a production-oriented AWS deployment for ReleaseGate:

- ECS Fargate cluster + service
- RDS PostgreSQL
- ElastiCache Redis (optional)
- CloudWatch log group
- Secrets Manager entries for database URL and internal service key

## Usage

```hcl
module "releasegate" {
  source = "./infra/terraform/releasegate"

  app_name           = "releasegate"
  environment_name   = "prod"
  aws_region         = "us-east-1"
  container_image    = "ghcr.io/your-org/releasegate:latest"

  vpc_id             = "vpc-123456"
  private_subnet_ids = ["subnet-a", "subnet-b"]

  execution_role_arn = "arn:aws:iam::123456789012:role/releasegateEcsExecutionRole"
  task_role_arn      = "arn:aws:iam::123456789012:role/releasegateTaskRole"

  db_instance_class  = "db.t3.micro"
  redis_enabled      = true

  environment = {
    RELEASEGATE_JWT_SECRET = "replace-me"
    RELEASEGATE_JWT_ISSUER = "releasegate"
  }
}
```

## Apply

```bash
terraform init
terraform plan
terraform apply
```

## Notes

- `db_password` is optional; if omitted, Terraform generates a random password.
- For enterprise usage, wire secrets from your existing secret-management workflow and keep plaintext credentials out of Terraform variables.
- Add ALB/Ingress in your root stack if public API ingress is required.
