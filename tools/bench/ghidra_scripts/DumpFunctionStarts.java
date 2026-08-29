// Headless post-script: write every recovered function entry point to JSON.
// Emits the memory block each entry lives in and the thunk/external flags so
// the benchmark decides what to score rather than baking the choice in here.
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;

public class DumpFunctionStarts extends GhidraScript {

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("DumpFunctionStarts: output path argument missing");
            return;
        }
        List<String> entries = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            Address entry = function.getEntryPoint();
            MemoryBlock block = currentProgram.getMemory().getBlock(entry);
            String blockName = block == null ? "" : block.getName();
            boolean executable = block != null && block.isExecute();
            entries.add(String.format(
                "{\"addr\": %d, \"block\": \"%s\", \"executable\": %s, \"thunk\": %s, \"external\": %s}",
                entry.getOffset(),
                escape(blockName),
                executable ? "true" : "false",
                function.isThunk() ? "true" : "false",
                function.isExternal() ? "true" : "false"));
        }
        long imageBase = currentProgram.getImageBase().getOffset();
        try (PrintWriter writer = new PrintWriter(args[0], "UTF-8")) {
            writer.println("{");
            writer.println("  \"program\": \"" + escape(currentProgram.getName()) + "\",");
            writer.println("  \"language\": \"" + escape(currentProgram.getLanguageID().getIdAsString()) + "\",");
            writer.println("  \"image_base\": " + imageBase + ",");
            writer.println("  \"ghidra_version\": \"" + escape(ghidra.framework.Application.getApplicationVersion()) + "\",");
            writer.println("  \"functions\": [");
            for (int i = 0; i < entries.size(); i++) {
                writer.println("    " + entries.get(i) + (i + 1 < entries.size() ? "," : ""));
            }
            writer.println("  ]");
            writer.println("}");
        }
        println("DumpFunctionStarts: wrote " + entries.size() + " entries to " + args[0]);
    }
}
