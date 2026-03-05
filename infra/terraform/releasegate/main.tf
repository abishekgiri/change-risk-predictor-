terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  name_prefix = "${var.app_name}-${var.environment_name}"
  common_tags = merge(
    {
      Application = var.app_name
      Environment = var.environment_name
      ManagedBy   = "terraform"
    },
    var.tags,
  )
}

resource "random_password" "db_password" {
  count            = var.db_password == "" ? 1 : 0
  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

locals {
  resolved_db_password = var.db_password != "" ? var.db_password : random_password.db_password[0].result
}

resource "aws_cloudwatch_log_group" "releasegate" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = 30
  tags              = local.common_tags
}

resource "aws_ecs_cluster" "releasegate" {
  name = "${local.name_prefix}-cluster"
  tags = local.common_tags
}

resource "aws_security_group" "releasegate_service" {
  name        = "${local.name_prefix}-svc-sg"
  description = "ReleaseGate ECS service security group"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = var.service_port
    to_port     = var.service_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "releasegate_db" {
  name        = "${local.name_prefix}-db-sg"
  description = "ReleaseGate PostgreSQL security group"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.releasegate_service.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_db_subnet_group" "releasegate" {
  name       = "${local.name_prefix}-db-subnets"
  subnet_ids = var.private_subnet_ids
  tags       = local.common_tags
}

resource "aws_db_instance" "releasegate" {
  identifier             = "${local.name_prefix}-db"
  allocated_storage      = var.db_allocated_storage
  engine                 = "postgres"
  engine_version         = "15"
  instance_class         = var.db_instance_class
  db_name                = var.db_name
  username               = var.db_username
  password               = local.resolved_db_password
  db_subnet_group_name   = aws_db_subnet_group.releasegate.name
  vpc_security_group_ids = [aws_security_group.releasegate_db.id]
  skip_final_snapshot    = true
  storage_encrypted      = true
  publicly_accessible    = false
  tags                   = local.common_tags
}

resource "aws_security_group" "releasegate_redis" {
  count       = var.redis_enabled ? 1 : 0
  name        = "${local.name_prefix}-redis-sg"
  description = "ReleaseGate Redis security group"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.releasegate_service.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_elasticache_subnet_group" "releasegate" {
  count      = var.redis_enabled ? 1 : 0
  name       = "${local.name_prefix}-redis-subnets"
  subnet_ids = var.private_subnet_ids
}

resource "aws_elasticache_replication_group" "releasegate" {
  count                      = var.redis_enabled ? 1 : 0
  replication_group_id       = replace("${local.name_prefix}-redis", "_", "-")
  replication_group_description = "ReleaseGate Redis"
  engine                     = "redis"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 1
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.releasegate[0].name
  security_group_ids         = [aws_security_group.releasegate_redis[0].id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  automatic_failover_enabled = false
  tags                       = local.common_tags
}

resource "aws_secretsmanager_secret" "database_url" {
  name = "${local.name_prefix}/database-url"
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = format(
    "postgresql://%s:%s@%s:%d/%s",
    var.db_username,
    local.resolved_db_password,
    aws_db_instance.releasegate.address,
    aws_db_instance.releasegate.port,
    var.db_name,
  )
}

resource "aws_secretsmanager_secret" "internal_service_key" {
  name = "${local.name_prefix}/internal-service-key"
  tags = local.common_tags
}

resource "random_password" "internal_service_key" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret_version" "internal_service_key" {
  secret_id     = aws_secretsmanager_secret.internal_service_key.id
  secret_string = random_password.internal_service_key.result
}

locals {
  environment_vars = [
    for key, value in merge(
      {
        RELEASEGATE_STORAGE_BACKEND = "postgres"
        RELEASEGATE_TENANT_ID       = "default"
      },
      var.environment,
    ) : {
      name  = key
      value = value
    }
  ]

  redis_host = var.redis_enabled ? aws_elasticache_replication_group.releasegate[0].primary_endpoint_address : ""
}

resource "aws_ecs_task_definition" "releasegate" {
  family                   = "${local.name_prefix}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = "releasegate"
      image     = var.container_image
      essential = true
      command   = ["uvicorn", "releasegate.server:app", "--host", "0.0.0.0", "--port", tostring(var.service_port)]
      portMappings = [
        {
          containerPort = var.service_port
          hostPort      = var.service_port
          protocol      = "tcp"
        }
      ]
      environment = concat(
        local.environment_vars,
        var.redis_enabled ? [{ name = "REDIS_URL", value = "redis://${local.redis_host}:6379/0" }] : [],
      )
      secrets = [
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
        { name = "RELEASEGATE_INTERNAL_SERVICE_KEY", valueFrom = aws_secretsmanager_secret.internal_service_key.arn },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.releasegate.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  tags = local.common_tags
}

resource "aws_ecs_service" "releasegate" {
  name            = "${local.name_prefix}-service"
  cluster         = aws_ecs_cluster.releasegate.id
  task_definition = aws_ecs_task_definition.releasegate.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    security_groups  = [aws_security_group.releasegate_service.id]
    subnets          = var.private_subnet_ids
    assign_public_ip = false
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  tags = local.common_tags
}
