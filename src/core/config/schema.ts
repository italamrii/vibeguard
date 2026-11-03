import { z } from 'zod';
import { CONFIDENCES, SEVERITIES } from '../findings/severity.ts';

const severity = z.enum(SEVERITIES);
const confidence = z.enum(CONFIDENCES);

const ruleSetting = z.union([
  z.literal('off'),
  z.literal('on'),
  z
    .object({
      enabled: z.boolean().optional(),
      severity: severity.optional(),
    })
    .strict(),
]);

/**
 * Schema for `.vibeguard.yml`. Objects are strict: an unknown key is an error, because
 * a typo such as `rule:` instead of `rules:` must not silently disable a check.
 */
export const configFileSchema = z
  .object({
    version: z.literal(1),
    ignore: z.array(z.string().min(1)).optional(),
    rules: z.record(z.string(), ruleSetting).optional(),
    failOn: z.union([severity, z.literal('none')]).optional(),
    minConfidence: confidence.optional(),
    discovery: z
      .object({
        skipBuildOutput: z.boolean().optional(),
        buildOutputDirs: z
          .array(
            z
              .string()
              .min(1)
              .regex(/^[^/\\]+$/, 'must be a directory name, not a path'),
          )
          .optional(),
      })
      .strict()
      .optional(),
    supabase: z
      .object({
        migrationsDirs: z.array(z.string().min(1)).optional(),
        exposedSchemas: z.array(z.string().min(1)).optional(),
      })
      .strict()
      .optional(),
    endpoints: z
      .object({
        authFunctions: z.array(z.string().min(1)).optional(),
        rateLimitFunctions: z.array(z.string().min(1)).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export type ConfigFile = z.infer<typeof configFileSchema>;
export type RuleSetting = z.infer<typeof ruleSetting>;
