import { z } from 'zod';

export const portScopeSchema = z.enum(['common', 'top100', 'top1000']);
export const scanProfileSchema = z.enum(['quick', 'standard', 'deep', 'custom']);
export const toolNameSchema = z.enum(['nmap', 'whatweb', 'wpscan', 'http', 'tls']);

export const customOptionsSchema = z
  .object({
    portScope: portScopeSchema,
    enabledTools: z.array(toolNameSchema).min(1),
    path: z.string().max(2048).default('/'),
    followRedirects: z.boolean().default(true),
    userAgent: z.string().max(512).optional(),
    timeoutMs: z.number().int().min(60_000).max(300_000).optional(),
  })
  .strict();

export const createJobSchema = z
  .object({
    target: z.string().min(1).max(2048),
    profile: scanProfileSchema,
    consent: z.literal(true, { errorMap: () => ({ message: 'Authorization acknowledgement is required.' }) }),
    custom: customOptionsSchema.optional(),
  })
  .strict();

export type CreateJobInput = z.infer<typeof createJobSchema>;
export type CustomOptionsInput = z.infer<typeof customOptionsSchema>;
