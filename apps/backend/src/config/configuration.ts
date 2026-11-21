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
  };
  jwt: {
    accessSecret: string;
    refreshSecret: string;
    accessExpiresIn: string;
    refreshExpiresIn: string;
  };
  aws: {
    region: string;
    s3Bucket: string;
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
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || undefined,
  },
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || 'dev_jwt_access_secret_min_32_characters_long',
    refreshSecret:
      process.env.JWT_REFRESH_SECRET || 'dev_jwt_refresh_secret_min_32_characters_long',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
    s3Bucket: process.env.AWS_S3_BUCKET || 'dcmp-evidence-dev',
  },
});
