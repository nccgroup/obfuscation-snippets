import logging
from miasm2.arch.x86.ira import ir_a_x86_32
from miasm2.analysis.data_flow import DiGraphDefUse, ReachingDefinitions, dead_simp_useful_assignblks, AssignblkNode
from utils import Pass, log_level

# This class allows us to set non-volatile regs
class ir_a_x86_32_win(ir_a_x86_32):

  def __init__(self, symbol_pool=None):
    ir_a_x86_32.__init__(self, symbol_pool)
    self.non_volatiles = set([self.arch.regs.EBX, self.arch.regs.ESI, self.arch.regs.EDI])

  def get_out_regs(self, _):
    return set([self.ret_reg, self.sp]) | self.non_volatiles

class UselessInstructions(Pass):

  def __init__(self, unflat):
    super(UselessInstructions, self).__init__(unflat)

  def remove_useless_instructions(self):
    self.logger.info('--------------------- DEAD INSTRUCTIONS ---------------------')
    graph = self.disas.graph
    counter = 0
    modified = False
    # dict(instruction->irs)
    instr_irs = {}
    # Create IRA for graph
    ira = ir_a_x86_32_win(self.disas.mdis.symbol_pool)
    # Add all IR blocks
    for block in graph:
      if block not in self.disas.rawblocks:
        irbs = ira.add_block(block)
        # Compute dict(instruction->irs)
        for irb in irbs:
          for ir in irb.assignblks:
            instr_irs.setdefault(ir.instr, set()).add(ir)
    nb_instructions = len(instr_irs)
    # Compute defs
    reaching_defs = ReachingDefinitions(ira)
    defuse = DiGraphDefUse(reaching_defs, deref_mem=True)
    useful = set(dead_simp_useful_assignblks(defuse, reaching_defs))
    # For all blocks
    useless_irs = set()
    for irb in ira.blocks.itervalues():
      # For each assignement
      for idx, assignblk in enumerate(irb.assignblks):
        # Get all the l-values (modified)
        all_lval_useless = True
        for lval in assignblk:
          # Check if this assignment node is useful
          if AssignblkNode(irb.label, idx, lval) in useful:
            all_lval_useless = False
            break
        if all_lval_useless:
          useless_irs.add(assignblk)
    # If all irs for a given instruction are useless
    # TODO: OR it's mov eax, eax
    useless = set()
    for instr, irs in instr_irs.iteritems():
      if irs.issubset(useless_irs):
        useless.add(instr)
    for block in graph:
      if block not in self.disas.rawblocks:
        for instr in block.lines:
          #if instr.name=='NOP' or instr in useless:
          if instr in useless:
            block.lines.remove(instr)
            counter+=1
            self.logger.debug(hex(instr.offset) + ' USELESS INSTR: ' + str(instr))
            modified = True
    self.logger.info('Removed %u instructions (%u total left)' % (counter, nb_instructions-counter))
    return modified

  def __call__(self):
    # pass to remove useless instructions
    modified = True
    while modified:
      modified = self.remove_useless_instructions()
