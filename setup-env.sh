#!/bin/bash
set -e

PROJECT="seekosint"
ENV="production"

echo "Setting up environment variables for $PROJECT..."

# GrayHatWarfare keys
for i in {1..18}; do
  KEY_VAR="GRAYHATWARFARE_API_KEY_$i"
  USER_VAR="GRAYHATWARFARE_USERNAME_$i"
  KEY_VALUE=$(grep "^$KEY_VAR=" .env | cut -d'=' -f2)
  USER_VALUE=$(grep "^$USER_VAR=" .env | cut -d'=' -f2)
  
  echo "$KEY_VAR"
  echo "$KEY_VALUE" | wrangler pages secret put "$KEY_VAR" --project-name="$PROJECT" --env="$ENV"
  
  echo "$USER_VAR"
  echo "$USER_VALUE" | wrangler pages secret put "$USER_VAR" --project-name="$PROJECT" --env="$ENV"
done

# NVD API Key
echo "NVD_API_KEY"
grep "^NVD_API_KEY=" .env | cut -d'=' -f2 | wrangler pages secret put NVD_API_KEY --project-name="$PROJECT" --env="$ENV"

# abuse.ch Key
echo "ABUSECH_KEY"
grep "^ABUSECH_KEY=" .env | cut -d'=' -f2 | wrangler pages secret put ABUSECH_KEY --project-name="$PROJECT" --env="$ENV"

echo "✅ All environment variables set!"
