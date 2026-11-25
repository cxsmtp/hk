// Lets a node:test file import the console's TypeScript modules as a production build sees them (see
// ts-alias-loader.mjs for the rules). module.register works from Node 20.6, so CI and the images' Node 20 run it.
import { register } from "node:module";

export function registerProductionAliases() {
  register("./ts-alias-loader.mjs", import.meta.url);
}
