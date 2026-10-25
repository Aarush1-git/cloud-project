// AWS Lambda (Node.js 20) - returns a presigned S3 PUT URL.
// Env vars: BUCKET (bucket name), PASSCODE (shared secret).
// Configure CORS on the Function URL settings (not in this code).
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const s3 = new S3Client({});
const H = { 'Content-Type': 'application/json' };
const reply = (statusCode, obj) => ({ statusCode, headers: H, body: JSON.stringify(obj) });

export const handler = async (event) => {
  try {
    const { passcode, key } = JSON.parse(event.body || '{}');
    if (passcode !== process.env.PASSCODE) return reply(403, { error: 'bad passcode' });
    if (!/^files\/[\w-]{1,16}\/[\w-]{1,32}\.(enc|json)$/.test(key || '')) return reply(400, { error: 'bad key' });
    const url = await getSignedUrl(
      s3, new PutObjectCommand({ Bucket: process.env.BUCKET, Key: key }), { expiresIn: 300 });
    return reply(200, { url });
  } catch (e) {
    return reply(500, { error: 'server error' });
  }
};
