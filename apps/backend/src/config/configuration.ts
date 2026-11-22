export interface AppConfig {
  nodeEnv: string;
  port: number;
  apiPrefix: string;
  corsOrigin: string[];
  database: {
    url: string;
  };
  redis: {
    host: string;
    port: number;
    password?: string;
    db: number;
    driver: string;
    required: boolean;
  };
  jwt: {
    accessSecret: string;
    refreshSecret: string;
    accessExpiresIn: string;
    refreshExpiresIn: string;
  };
  auth: {
    publicOrigin?: string;
  };
  aws: {
    region: string;
    s3Bucket: string;
  };
  kms: {
    driver: string;
    accessTokenKeyId?: string;
    ssaHmacKeyId?: string;
    refreshMasterKeyId?: string;
  };
}

export default (): AppConfig => ({
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '4000', 10),
  apiPrefix: process.env.API_PREFIX || '/api/v1',
  corsOrigin: (process.env.CORS_ORIGIN || 'http://localhost:3000,http://localhost:3001').split(','),
  database: {
    url:
      process.env.DATABASE_URL ||
      'postgresql://dcmp_user:dcmp_dev_password@localhost:5432/dcmp_dev?schema=public',
  },
  redis: {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || undefined,
    db: parseInt(process.env.REDIS_DB || '0', 10),
    driver: process.env.AUTH_REDIS_DRIVER || (process.env.REDIS_HOST ? 'real' : 'memory'),
    required: process.env.AUTH_REDIS_REQUIRED === 'true' || process.env.NODE_ENV === 'production',
  },
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || 'dev_jwt_access_secret_min_32_characters_long',
    refreshSecret:
      process.env.JWT_REFRESH_SECRET || 'dev_jwt_refresh_secret_min_32_characters_long',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
  auth: {
    publicOrigin: process.env.DCMP_PUBLIC_ORIGIN || undefined,
  },
  aws: {
    region: process.env.DCMP_KMS_REGION || process.env.AWS_REGION || 'us-east-1',
    s3Bucket: process.env.AWS_S3_BUCKET || 'dcmp-evidence-dev',
  },
  kms: {
    driver: process.env.AUTH_CRYPTO_DRIVER || 'local',
    accessTokenKeyId: process.env.DCMP_KMS_ACCESS_TOKEN_KEY_ID || undefined,
    ssaHmacKeyId: process.env.DCMP_KMS_SSA_HMAC_KEY_ID || undefined,
    refreshMasterKeyId: process.env.DCMP_KMS_REFRESH_MASTER_KEY_ID || undefined,
  },
});
