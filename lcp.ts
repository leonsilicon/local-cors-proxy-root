#!/usr/bin/env node
import commandLineArgs from "command-line-args";
import { startProxy } from "./lib.ts";

type CliOptions = {
  port: number;
  proxyPartial: string;
  proxyUrl?: string;
  credentials: boolean;
  origin: string;
  rejectUnauthorized: number;
};

const optionDefinitions = [
  { name: "port", alias: "p", type: Number, defaultValue: 8010 },
  { name: "proxyPartial", type: String, defaultValue: "/proxy" },
  { name: "proxyUrl", type: String },
  { name: "credentials", type: Boolean, defaultValue: false },
  { name: "origin", type: String, defaultValue: "*" },
  { name: "rejectUnauthorized", type: Number, defaultValue: 0 },
];

const run = async (): Promise<void> => {
  const options = commandLineArgs(optionDefinitions) as CliOptions;

  if (!options.proxyUrl) {
    throw new Error("--proxyUrl is required");
  }

  await startProxy({
    port: options.port,
    proxyUrl: options.proxyUrl,
    proxyPartial: options.proxyPartial,
    credentials: options.credentials,
    origin: options.origin,
    rejectUnauthorized: Boolean(options.rejectUnauthorized),
  });
};

run().catch((error) => {
  console.error(error);
});
