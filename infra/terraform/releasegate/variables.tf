variable "app_name" {
  description = "Base application name used for resource naming"
  type        = string
  default     = "releasegate"
}

variable "environment_name" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "container_image" {
  description = "Container image for the ReleaseGate API service"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for deployment"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs used by ECS and databases"
  type        = list(string)
}

variable "service_port" {
  description = "Container and service port for API traffic"
  type        = number
  default     = 8000
}

variable "desired_count" {
  description = "Desired ECS service count"
  type        = number
  default     = 2
}

variable "cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory (MB)"
  type        = number
  default     = 1024
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "db_allocated_storage" {
  description = "Allocated storage for RDS (GB)"
  type        = number
  default     = 20
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "releasegate"
}

variable "db_username" {
  description = "Database username"
  type        = string
  default     = "releasegate"
}

variable "db_password" {
  description = "Database password (leave empty to auto-generate)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "redis_enabled" {
  description = "Enable Redis deployment"
  type        = bool
  default     = true
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t4g.micro"
}

variable "execution_role_arn" {
  description = "IAM role ARN for ECS task execution"
  type        = string
}

variable "task_role_arn" {
  description = "IAM role ARN assumed by the running task"
  type        = string
}

variable "environment" {
  description = "Additional environment variables passed into ReleaseGate"
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}
