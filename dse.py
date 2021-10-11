#!/usr/bin/python3
import z3
from miasm.core.locationdb import LocationDB
from miasm.analysis.dse import DSEEngine, DSEPathConstraint as DSEPC
from miasm.expression.expression import ExprId, ExprInt, ExprMem
from miasm.analysis.sandbox import Sandbox_Win_x86_64

snapshot=None
offsize_count=0
testval = b'\x40\x40'
runs = {}

class DSEPCC(DSEPC):
    def __init__(self, machine, loc_db, produce_solution=DSEPC.PRODUCE_SOLUTION_CODE_COV, known_solutions=None, **kwargs):
      super(DSEPCC, self).__init__(machine, loc_db, produce_solution, known_solutions, **kwargs)
      self.constraints = set()

    def handle_correct_destination(self, destination, path_constraints):
      super(DSEPCC, self).handle_correct_destination(destination, path_constraints)
      self.constraints|=path_constraints

def dse_attach(jitter):
  global offsize_count, snapshot
  if offsize_count==31:
    dse.attach(jitter)
    jitter.vm.set_mem(jitter.cpu.RBP, testval)
    dse.update_state_from_concrete()
    # Symbolize the first 4 bytes
    dse.update_state({ExprMem(ExprInt(jitter.cpu.RBP+i, 64), 8) : ExprId(f'BLOB{i}', 8) for i in range(2)})
    snapshot = dse.take_snapshot()
    jitter.exec_cb(jitter)
    jitter.remove_breakpoints_by_callback(dse_attach)
    print(f'[{jitter.pc:08X}]: 32 TEA iterations completed, deciphered bytes symbolized DSE attached, snapshot captured')
  offsize_count+=1
  return True

def stop_exec(jitter):
  # If we reached a new block
  for bbl, model in dse.new_solutions.items():
    # Capture the concrete value of each of the symbolized bytes
    candidate = bytearray(2)
    for i in range(2):
      bb = model.eval(dse.z3_trans.from_expr(dse.eval_expr(ExprId(f'BLOB{i}', 8))))
      candidate[i] = bb.as_long() if type(bb)==z3.z3.BitVecNumRef else current[i]
    todo.append(bytes(candidate))
  # Print offset value in function of blob
  symbolic_mem_access = dse.eval_expr(ExprId("RAX", 64))
  print(f'ENDRUN with OFFSET: {jitter.cpu.RAX:X} ({symbolic_mem_access})')
  runs.setdefault(symbolic_mem_access, dse.constraints).intersection(dse.constraints)
  dse.constraints = set() # reset
  #import pdb; pdb.set_trace()
  return False # This ends execution

def main():
  global dse, todo, current, runs
  # Create sandbox
  parser = Sandbox_Win_x86_64.parser(description='PE sandboxer')
  parser.add_argument('filename', help='PE Filename')
  options = parser.parse_args()
  options.load_hdr = True
  options.jitter = 'llvm'
  loc_db = LocationDB()
  sb = Sandbox_Win_x86_64(loc_db, options.filename, options, globals())
  # Create DSE
  #dse = DSEPCC(sb.machine, sb.loc_db, produce_solution=DSEPC.PRODUCE_SOLUTION_CODE_COV)
  dse = DSEPCC(sb.machine, sb.loc_db, produce_solution=DSEPC.PRODUCE_SOLUTION_PATH_COV)
  # Setup callbacks
  sb.jitter.add_breakpoint(0x140D58A5C, dse_attach)
  sb.jitter.add_breakpoint(0x140DEDF7C, stop_exec)
  # Start address
  sb.jitter.init_run(0x140E2928D)
  todo = [testval]
  # DSE loop
  while todo:
    if snapshot:
      current = todo.pop()
      dse.restore_snapshot(snapshot, keep_known_solutions=True)
      sb.jitter.vm.set_mem(sb.jitter.cpu.RBP, current)
      print('-'*40 + f' RUN with CONCRETE: {sb.jitter.vm.get_u16(sb.jitter.cpu.RBP):04X}')
    else:
      # First run to capture snapshot
      current = todo[0]
    sb.jitter.continue_run()
  for dest, constraints in runs.items():
    print('-'*40 + f' MEM ACCESS: {str(dest)}')
    for cons in constraints:
      print('  # ' + str(cons))
  import pdb; pdb.set_trace()

if __name__ == '__main__':
  main()
