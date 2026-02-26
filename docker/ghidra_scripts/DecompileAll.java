// DecompileAll.java — Ghidra headless post-analysis script for Softy.
// Decompiles every function and outputs one JSON object per line to stdout.
// Format: {"address":"0x...","name":"...","signature":"...","cCode":"...","disassembly":[...],"callers":[...],"callees":[...],"size":N}

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class DecompileAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        ifc.setSimplificationStyle("decompile");

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        int count = 0;
        for (Function func : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;

            String address   = func.getEntryPoint().toString();
            String name      = func.getName();
            String signature = func.getPrototypeString(true, false);
            long   size      = func.getBody().getNumAddresses();

            // Callers
            List<String> callers = new ArrayList<>();
            for (Reference ref : rm.getReferencesTo(func.getEntryPoint())) {
                if (ref.getReferenceType().isCall()) {
                    callers.add("0x" + ref.getFromAddress().toString());
                }
                if (callers.size() >= 20) break;
            }

            // Callees
            List<String> callees = new ArrayList<>();
            for (Function called : func.getCalledFunctions(null)) {
                callees.add("0x" + called.getEntryPoint().toString());
                if (callees.size() >= 20) break;
            }

            // Decompile
            String cCode = "";
            try {
                DecompileResults result = ifc.decompileFunction(func, 30, monitor);
                if (result != null && result.decompileCompleted()) {
                    cCode = result.getDecompiledFunction().getC();
                } else {
                    cCode = "// Decompilation failed or timed out for " + name + "\nvoid " + name + "(void) {}";
                }
            } catch (Exception e) {
                cCode = "// Error during decompilation: " + e.getMessage() + "\nvoid " + name + "(void) {}";
            }

            // Disassembly (first 200 instructions)
            StringBuilder disasm = new StringBuilder("[");
            InstructionIterator instructions = currentProgram.getListing()
                .getInstructions(func.getBody(), true);
            int instrCount = 0;
            while (instructions.hasNext() && instrCount < 200) {
                Instruction instr = instructions.next();
                String addrStr = "0x" + instr.getAddress().toString();
                String mnem    = instr.getMnemonicString();
                String ops     = instr.getDefaultOperandRepresentationList(0) != null
                    ? instr.toString().replace(mnem, "").trim()
                    : "";
                if (instrCount > 0) disasm.append(",");
                disasm.append("{\"addr\":\"").append(addrStr).append("\",")
                      .append("\"mnem\":\"").append(escapeJson(mnem)).append("\",")
                      .append("\"ops\":\"").append(escapeJson(ops)).append("\"}");
                instrCount++;
            }
            disasm.append("]");

            // Emit JSON line
            System.out.println("{"
                + "\"address\":\"0x" + address + "\","
                + "\"name\":" + jsonString(name) + ","
                + "\"signature\":" + jsonString(signature) + ","
                + "\"size\":" + size + ","
                + "\"callers\":" + jsonStringArray(callers) + ","
                + "\"callees\":" + jsonStringArray(callees) + ","
                + "\"disassembly\":" + disasm.toString() + ","
                + "\"cCode\":" + jsonString(cCode)
                + "}");

            count++;
        }

        ifc.dispose();
        System.err.println("[Softy] Decompiled " + count + " functions.");
    }

    private String jsonString(String s) {
        if (s == null) return "\"\"";
        return "\"" + escapeJson(s) + "\"";
    }

    private String jsonStringArray(List<String> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(list.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
