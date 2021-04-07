import { readline } from "https://deno.land/x/readline@v1.1.0/mod.ts";
import { emptyDirSync } from "https://deno.land/std@0.78.0/fs/mod.ts";

let funcFolder = `${Deno.args[0]}_funcs`;
let extracted = 0;
async function extract(f: Deno.File) {
  let nextFunctionName = "";
  let funcBody = "";
  for await (const line of readline(f)) {
    const LineClearText = new TextDecoder().decode(line);
    if (LineClearText.includes("FUN") && LineClearText.split("(")[0].replace(/ /g, "")[0] !=="F") {
      LineClearText.split(" ").forEach((word) => {
        if (
          !nextFunctionName.length &&
          word.includes("FUN") &&
          !word.includes(";")
        )
          nextFunctionName = word.split("(")[0];
      });
    } else if (LineClearText[0] === "}") {
      extracted++;
      try {
        nextFunctionName.length &&
          nextFunctionName.includes("14") &&
          !nextFunctionName.includes("*") &&
          !nextFunctionName.includes("0x") &&
          Deno.writeTextFileSync(
            `${funcFolder}/${nextFunctionName}.cpp`,
            funcBody
          );
      } catch (error) {
        console.log("error with func : ", nextFunctionName);
        extracted--;
      }
      nextFunctionName = "";
      funcBody = "";
    } else {
      LineClearText[0] !== "{" ? (funcBody += LineClearText + "\n") : null;
    }
  }
  f.close();
}

if (Deno.args[0]) {
  const f = await Deno.open(Deno.args[0]);
  emptyDirSync(funcFolder);
  console.log("Extracting... This can take time");
  console.time("Extraction time");
  await extract(f);
  console.timeEnd("Extraction time");
  console.log(`Extracted funcs: ${extracted}`);
} else {
  console.error("Missing file path !");
  console.log(
    "deno run -A extractFuncs {the path or the file you wanna extract funcs from}"
  );
  console.log("or if you use .exe");
  console.log(
    "extractFuncs.exe {the path or the file you wanna extract funcs from}"
  );
  prompt("");
  Deno.exit();
}
