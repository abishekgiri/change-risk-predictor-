output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.releasegate.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.releasegate.name
}

output "database_endpoint" {
  description = "RDS endpoint address"
  value       = aws_db_instance.releasegate.address
}

output "redis_endpoint" {
  description = "Redis endpoint (empty when redis_enabled=false)"
  value       = var.redis_enabled ? aws_elasticache_replication_group.releasegate[0].primary_endpoint_address : ""
}

output "database_secret_arn" {
  description = "Secrets Manager ARN containing the postgres DSN"
  value       = aws_secretsmanager_secret.database_url.arn
}

output "internal_service_key_secret_arn" {
  description = "Secrets Manager ARN containing ReleaseGate internal service key"
  value       = aws_secretsmanager_secret.internal_service_key.arn
}
