module.exports = {
  apps: [{
    name: 'openai-pool',
    script: 'run.py',
    interpreter: '/Users/caolin/Desktop/projects/openai_pool_orchestrator_v5/venv/bin/python3',
    cwd: '/Users/caolin/Desktop/projects/openai_pool_orchestrator_v5',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    error_file: './logs/pm2-error.log',
    out_file: './logs/pm2-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    merge_logs: true,
    env: {
      NODE_ENV: 'production'
    }
  }]
};
