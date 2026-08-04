resource "random_password" "db_master" {
  length  = 24
  special = true
  # RDS rejects '/', '@', '"', and spaces in MasterUserPassword.
  override_special = "!#$%&*+-.:=?^_"
}

resource "random_password" "dvwa_app" {
  length  = 32
  special = false
}

resource "aws_db_instance" "primary" {
  provider = aws.primary

  identifier            = "${local.name}-primary"
  engine                = "mariadb"
  instance_class        = var.db_instance_class
  allocated_storage     = 20
  max_allocated_storage = 100
  db_name               = var.db_name
  username              = var.db_username
  # MariaDB cross-region read replicas do not support a source instance whose
  # master password is managed by RDS/Secrets Manager.
  # Omitting manage_master_user_password selects the user-managed password mode.
  password                = random_password.db_master.result
  multi_az                = local.primary_rds_multi_az
  db_subnet_group_name    = module.primary_vpc.database_subnet_group_name
  vpc_security_group_ids  = [aws_security_group.primary_data.id]
  storage_encrypted       = true
  backup_retention_period = 7
  # The training environment is intentionally disposable. The daily wrapper
  # guards the destroy operation and rebuilds an empty DVWA database next time.
  deletion_protection = false
  skip_final_snapshot = true
  publicly_accessible = false
}

resource "aws_kms_key" "dr_rds" {
  count                   = local.enable_dr_runtime ? 1 : 0
  provider                = aws.dr
  description             = "KMS key for the cross-region RDS replica"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "dr_rds" {
  count         = local.enable_dr_runtime ? 1 : 0
  provider      = aws.dr
  name          = "alias/${local.name}-dr-rds"
  target_key_id = aws_kms_key.dr_rds[0].key_id
}

resource "aws_db_instance" "dr_replica" {
  count    = local.enable_dr_runtime ? 1 : 0
  provider = aws.dr

  identifier             = "${local.name}-dr-replica"
  replicate_source_db    = aws_db_instance.primary.arn
  instance_class         = var.db_instance_class
  db_subnet_group_name   = module.dr_vpc[0].database_subnet_group_name
  vpc_security_group_ids = [aws_security_group.dr_data[0].id]
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.dr_rds[0].arn
  publicly_accessible    = false
  skip_final_snapshot    = true
}

resource "aws_elasticache_subnet_group" "primary" {
  count      = var.enable_valkey ? 1 : 0
  provider   = aws.primary
  name       = "${local.name}-primary"
  subnet_ids = module.primary_vpc.database_subnets
}

resource "aws_elasticache_replication_group" "primary" {
  count    = var.enable_valkey ? 1 : 0
  provider = aws.primary

  replication_group_id       = "${local.name}-primary"
  description                = "Primary Valkey cache"
  engine                     = "valkey"
  node_type                  = "cache.t4g.micro"
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  subnet_group_name          = aws_elasticache_subnet_group.primary[0].name
  security_group_ids         = [aws_security_group.primary_data.id]
}

resource "aws_elasticache_subnet_group" "dr" {
  count      = local.enable_dr_runtime && var.enable_valkey ? 1 : 0
  provider   = aws.dr
  name       = "${local.name}-dr"
  subnet_ids = module.dr_vpc[0].database_subnets
}

resource "aws_elasticache_replication_group" "dr" {
  count    = local.enable_dr_runtime && var.enable_valkey ? 1 : 0
  provider = aws.dr

  replication_group_id       = "${local.name}-dr"
  description                = "DR Valkey cache"
  engine                     = "valkey"
  node_type                  = "cache.t4g.micro"
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  subnet_group_name          = aws_elasticache_subnet_group.dr[0].name
  security_group_ids         = [aws_security_group.dr_data[0].id]
}
