import { object, string } from "zod"
import bcrypt from 'bcrypt';
const passwordSchema = string({ required_error: "Password is required" })
.min(1, "Password is required")
.min(6, "Password must be more than 8 characters")
.max(32, "Password must be less than 32 characters");

const emailSchema = string({ required_error: "Email is required" })
.min(1, "Email is required")
.email("Invalid email");

export const signInSchema = object({
  username: string({ required_error: "Username is required" })
    .min(4, "Needs to be at least 4 characters long"),
  email: emailSchema,
  password: passwordSchema,
  confirm: passwordSchema
}).superRefine(({ confirm, password }, ctx) => {
  if (confirm !== password) {
    ctx.addIssue({
      code: "custom",
      message: "The passwords did not match",
      path: ['confirm']
    });
  }
});

export const loginSchema = object({ email: emailSchema, password: passwordSchema });

export function generateHash(password: string): string {
  const saltRounds = 10
  return bcrypt.hashSync(password, saltRounds)
}

export function compareHash(plainPassword: string, hash: string): boolean {
  return bcrypt.compareSync(plainPassword, hash)
}