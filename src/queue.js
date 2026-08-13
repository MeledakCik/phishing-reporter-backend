import dotenv from 'dotenv';
import { processForensicJob } from './worker.js';

dotenv.config();

const REDIS_URL = process.env.REDIS_URL;

class MemoryQueue {
  constructor() {
    this.jobs = [];
    this.running = false;
  }

  async add(name, data) {
    const job = { name, data, id: Math.random().toString(36).substring(7) };
    this.jobs.push(job);
    console.log(`[MemoryQueue] Job added: ${name} (ID: ${job.id})`);
    
    // Start queue worker if not running
    if (!this.running) {
      this.work();
    }
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

// Initialize queue
export async function getQueue() {
  if (queueInstance) {
    return queueInstance;
  }

  if (REDIS_URL) {
    try {
      const { Queue } = await import('bullmq');
      const ioredis = await import('ioredis');
      const Redis = ioredis.default || ioredis;
      const connection = new Redis(REDIS_URL);
      
      const bullQueue = new Queue('forensics', { connection });
      console.log('[Queue] Initialized BullMQ Redis Queue.');
      
      // Initialize BullMQ Worker in background
      const { Worker } = await import('bullmq');
      const worker = new Worker('forensics', async (job) => {
        console.log(`[BullMQ Worker] Processing job ${job.id}`);
        await processForensicJob(job.data);
      }, { connection });

      worker.on('completed', (job) => {
        console.log(`[BullMQ Worker] Job ${job.id} completed`);
      });

      worker.on('failed', (job, err) => {
        console.error(`[BullMQ Worker] Job ${job?.id} failed`, err);
      });

      queueInstance = {
        add: async (name, data) => {
          return await bullQueue.add(name, data);
        }
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
