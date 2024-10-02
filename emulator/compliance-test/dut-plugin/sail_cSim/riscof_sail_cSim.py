#++
#
# Copyright (c) 2020. RISC-V International. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation and/or
#    other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#--
import os
import shutil
import logging

import riscof.utils as utils
from riscof.pluginTemplate import pluginTemplate
import riscof.constants as constants
from riscv_isac.isac import isac

logger = logging.getLogger()

class sail_cSim(pluginTemplate):
    __model__ = 'sail_c_simulator'
    __version__ = 'v20240429_151500'

    def __init__(self, *args, **kwargs):
        sclass = super().__init__(*args, **kwargs)

        config = kwargs.get('config')
        if config is None:
            logger.error('Config node for sail_cSim missing.')
            raise SystemExit(1)
        self.num_jobs = str(config['jobs'] if 'jobs' in config else 1)
        self.pluginpath = os.path.abspath(config['pluginpath'])
        self.sail_exe = {
            '32': os.environ.get('RISCV_SIM_RV32',
                os.path.join(config['PATH'] if 'PATH' in config else '', 'riscv_sim_RV32')),
            '64': os.environ.get('RISCV_SIM_RV64',
                os.path.join(config['PATH'] if 'PATH' in config else '', 'riscv_sim_RV64')),
        }
        self.isa_spec = os.path.abspath(config['ispec']) if 'ispec' in config else ''
        self.platform_spec = os.path.abspath(config['pspec']) if 'ispec' in config else ''
        self.make = config['make'] if 'make' in config else 'make'
        logger.debug('SAIL CSim plugin initialised using the following configuration.')
        for entry in config:
            logger.debug(entry+' : '+config[entry])
        return sclass

    def initialise(self, suite, work_dir, archtest_env):
        self.compiler_path = os.environ.get('RISCV_CC',
            'riscv64-unknown-elf-gcc')
        self.objdump_path = os.environ.get('RISCV_OBJDUMP',
            'riscv64-unknown-elf-objdump')

        self.suite = suite
        self.work_dir = work_dir
        self.objdump_cmd = '{0} -D {1} > {2};'
        self.compile_cmd = '{0} -march={1} \
         -DXLEN={2} -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles \
         -T '+self.pluginpath+'/../env/link.ld \
         -I '+self.pluginpath+'/../env/ \
         -I ' + archtest_env

    def build(self, isa_yaml, platform_yaml):
        ispec = utils.load_yaml(isa_yaml)['hart0']
        self.xlen = ('64' if 64 in ispec['supported_xlen'] else '32')
        self.isa = 'rv' + self.xlen
        self.compile_cmd = self.compile_cmd + \
            ' -mabi=' + \
            ('lp64 ' if 64 in ispec['supported_xlen'] else 'ilp32 ')
        if 'I' in ispec['ISA']:
            self.isa += 'i'
        if 'M' in ispec['ISA']:
            self.isa += 'm'
        if 'C' in ispec['ISA']:
            self.isa += 'c'
        if 'A' in ispec['ISA']:
            self.isa += 'a'
        if 'F' in ispec['ISA']:
            self.isa += 'f'
        if 'D' in ispec['ISA']:
            self.isa += 'd'
        if shutil.which(self.objdump_path) is None:
            logger.error(self.objdump_path + \
                ': executable not found. Please check environment setup.')
            raise SystemExit(1)
        if shutil.which(self.compiler_path) is None:
            logger.error(self.compiler_path + \
                ': executable not found. Please check environment setup.')
            raise SystemExit(1)
        if shutil.which(self.sail_exe[self.xlen]) is None:
            logger.error(self.sail_exe[self.xlen] + \
                ': executable not found. Please check environment setup.')
            raise SystemExit(1)
        if shutil.which(self.make) is None:
            logger.error(self.make + \
                ': executable not found. Please check environment setup.')
            raise SystemExit(1)


    def runTests(self, testList, cgf_file=None):
        if os.path.exists(self.work_dir + '/Makefile.' + self.name[:-1]):
            os.remove(self.work_dir + '/Makefile.' + self.name[:-1])
        make = utils.makeUtil(makefilePath=os.path.join(self.work_dir, 'Makefile.' + self.name[:-1]))
        make.makeCommand = self.make + ' -j' + self.num_jobs
        for file in testList:
            testentry = testList[file]
            test = testentry['test_path']
            test_dir = testentry['work_dir']
            test_name = test.rsplit('/',1)[1][:-2]

            elf = 'ref.elf'

            execute = '@cd '+testentry['work_dir']+';'

            cmd = self.compile_cmd.format(
                self.compiler_path,
                testentry['isa'].lower(),
                self.xlen) + \
                ' ' + test + ' -o ' + elf
            compile_cmd = cmd + ' -D' + ' -D'.join(testentry['macros'])
            execute+=compile_cmd+';'

            execute += self.objdump_cmd.format(self.objdump_path, elf, 'ref.disass')
            sig_file = os.path.join(test_dir, self.name[:-1] + '.signature')

            execute += self.sail_exe[self.xlen] + \
                ' --test-signature={0} {1} > {2}.log 2>&1;'.format(
                    sig_file, elf, test_name)
            cov_str = ' '
            for label in testentry['coverage_labels']:
                cov_str+=' -l '+label

            if cgf_file is not None:
                coverage_cmd = 'riscv_isac --verbose info coverage -d \
                        -t {0}.log --parser-name c_sail -o coverage.rpt  \
                        --sig-label begin_signature  end_signature \
                        --test-label rvtest_code_begin rvtest_code_end \
                        -e ref.elf -c {1} -x{2} {3};'.format(\
                        test_name, ' -c '.join(cgf_file), self.xlen, cov_str)
            else:
                coverage_cmd = ''


            execute+=coverage_cmd

            make.add_target(execute)

        make.execute_all(self.work_dir)
