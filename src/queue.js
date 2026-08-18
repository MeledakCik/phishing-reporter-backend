import dotenv from 'dotenv';
import { processForensicJob } from './worker.js';

dotenv.config();

const REDIS_URL = process.env.REDIS_URL; // contoh: redis://user_user0zx8kgsa:2HnSOxouWpRHUMCFEE6r@host:6379
const REDIS_PREFIX = process.env.REDIS_PREFIX || 'user_user0zx8kgsa';

class MemoryQueue {
  constructor() {
    this.jobs = [];
    this.running = false;
  }
  async add(name, data) {
    const job = { name, data, id: Math.random().toString(36).substring(7) };
    this.jobs.push(job);
    console.log(`[MemoryQueue] Job added: ${name} (ID: ${job.id})`);
    if (!this.running) this.work();
    return job;
  }
  async work() {
    this.running = true;
    while (this.jobs.length > 0) {
      const job = this.jobs.shift();
      console.log(`[MemoryQueue] Processing job: ${job.name} (ID: ${job.id})`);
      try {
        await processForensicJob(job.data);
        console.log(`[MemoryQueue] Job completed: ${job.name} (ID: ${job.id})`);
      } catch (err) {
        console.error(`[MemoryQueue] Job failed: ${job.name} (ID: ${job.id})`, err);
      }
    }
    this.running = false;
  }
}

let queueInstance = null;
let workerInstance = null;

// Factory connection biar BullMQ gak share 1 koneksi (wajib pisah)
async function createRedisConnection() {
  const ioredis = await import('ioredis');
  const Redis = ioredis.default || ioredis;
  
  // Fix: parse username dari URL kalau ada, biar gak WRONGPASS
  // ioredis otomatis parse redis://user:pass@host tapi kita explicit juga
  const conn = new Redis(REDIS_URL, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false, // FIX INFO NOPERM
    enableOfflineQueue: false,
    // BullMQ butuh ini
    lazyConnect: false,
  });

  conn.on('error', (err) => {
    if (!err.message.includes('NOPERM')) {
      console.error('[Redis]', err.message);
    }
  });

  return conn;
}

export async function getQueue() {
  if (queueInstance) return queueInstance;

  if (REDIS_URL) {
    try {
      const { Queue, Worker, QueueEvents } = await import('bullmq');

      // PENTING: 2 koneksi terpisah untuk Queue & Worker (requirement BullMQ)
      const queueConnection = await createRedisConnection();
      const workerConnection = await createRedisConnection();

      // FIX NOPERM: prefix harus lolos ACL ~user_user0zx8kgsa:* ~bull:*
      // Sebelumnya: bull:forensics:* -> sekarang: user_user0zx8kgsa:bull:forensics:*
      const BULL_PREFIX = `${REDIS_PREFIX}:bull`;

      const bullQueue = new Queue('forensics', {
        connection: queueConnection,
        prefix: BULL_PREFIX,
      });
      console.log(`[Queue] Initialized BullMQ Redis Queue with prefix: ${BULL_PREFIX}:forensics`);

      // Worker hanya init sekali
      if (!workerInstance) {
        workerInstance = new Worker('forensics', async (job) => {
          console.log(`[BullMQ Worker] Processing job ${job.id} (${job.name})`);
          await processForensicJob(job.data);
        }, {
          connection: workerConnection,
          prefix: BULL_PREFIX,
          concurrency: 5,
        });

        workerInstance.on('completed', (job) => {
          console.log(`[BullMQ Worker] Job ${job.id} completed`);
        });
        workerInstance.on('failed', (job, err) => {
          console.error(`[BullMQ Worker] Job ${job?.id} failed`, err.message);
        });
        workerInstance.on('error', (err) => {
          // Filter NOPERM biar gak spam log
          if (err.message.includes('NOPERM')) {
            console.error('[BullMQ Worker] NOPERM - Cek ACL ~bull:*', err.message);
          } else {
            console.error('[BullMQ Worker] Error', err);
          }
        });

        // Optional: events
        const events = new QueueEvents('forensics', {
          connection: await createRedisConnection(),
          prefix: BULL_PREFIX,
        });
      }

      queueInstance = {
        add: async (name, data) => {
          return await bullQueue.add(name, data, {
            attempts: 3,
            backoff: { type: 'exponential', delay: 5000 },
            removeOnComplete: 100,
            removeOnFail: 50,
          });
        },
        // expose raw queue buat debug
        _raw: bullQueue,
      };
    } catch (err) {
      console.warn('[Queue] Failed to connect to Redis. Falling back to Memory Queue.', err.message);
      queueInstance = new MemoryQueue();
    }
  } else {
    console.log('[Queue] No REDIS_URL provided. Using in-memory fallback queue.');
    queueInstance = new MemoryQueue();
  }

  return queueInstance;
}
