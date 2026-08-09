import { z } from 'zod';

export const portScopeSchema = z.enum(['common', 'top100', 'top1000']);
export const scanProfileSchema = z.enum(['quick', 'standard', 'deep', 'custom']);
export const toolNameSchema = z.enum(['nmap', 'whatweb', 'wpscan', 'http', 'tls', 'subfinder', 'dnsx', 'rdap', 'nuclei', 'retire', 'testssl', 'feroxbuster', 'osv']);
export const baseToolNameSchema = z.enum(['nmap', 'whatweb', 'wpscan', 'http', 'tls']);
export const moduleIdSchema = z.enum(['asset-discovery', 'vuln-scan', 'tls-hardening', 'content-discovery', 'cve-context']);

export const customOptionsSchema = z
  .object({
    portScope: portScopeSchema,
    enabledTools: z.array(baseToolNameSchema).min(1),
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
    modules: z.array(moduleIdSchema).max(5).optional(),
  })
  .strict();

export type CreateJobInput = z.infer<typeof createJobSchema>;
export type CustomOptionsInput = z.infer<typeof customOptionsSchema>;
export type ModuleInput = z.infer<typeof moduleIdSchema>;
