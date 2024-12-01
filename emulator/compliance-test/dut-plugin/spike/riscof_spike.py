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

import logging
import os
import shutil

import riscof.utils as utils
import riscof.constants as constants
from riscof.pluginTemplate import pluginTemplate


logger = logging.getLogger()


class spike(pluginTemplate):
    __model__ = 'spike'

    __version__ = 'v20240429_151500'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        config = kwargs.get('config')

        # If the config node for this DUT is missing or empty. Raise an error. At minimum we need
        # the paths to the ispec and pspec files
        if config is None:
            print('Please enter input file paths in configuration.')
            raise SystemExit(1)

        # In case of an RTL based DUT, this would be point to the final binary executable of your
        # test-bench produced by a simulator (like verilator, vcs, incisive, etc). In case of an iss or
        # emulator, this variable could point to where the iss binary is located. If 'PATH variable
        # is missing in the config.ini we can hardcode the alternate here.
        self.dut_exe = os.environ.get(
            'RISCV_SPIKE',
            os.path.join(config['PATH'] if 'PATH' in config else '', 'spike'))

        # Number of parallel jobs that can be spawned off by RISCOF
        # for various actions performed in later functions, specifically to run the tests in
        # parallel on the DUT executable. Can also be used in the build function if required.
        self.num_jobs = str(config['jobs'] if 'jobs' in config else 1)

        # Path to the directory where this python file is located. Collect it from the config.ini
        self.pluginpath=os.path.abspath(config['pluginpath'])

        # Collect the paths to the  riscv-config absed ISA and platform yaml files. One can choose
        # to hardcode these here itself instead of picking it from the config.ini file.
        self.isa_spec = os.path.abspath(config['ispec'])
        self.platform_spec = os.path.abspath(config['pspec'])


    def initialise(self, suite, work_dir, archtest_env):
       # capture the working directory. Any artifacts that the DUT creates should be placed in this
       # directory. Other artifacts from the framework and the Reference plugin will also be placed
       # here itself.
       self.work_dir = work_dir

       # capture the architectural test-suite directory.
       self.suite_dir = suite

       # Get compiler from environment
       self.compiler_path = os.environ.get('RISCV_CC',
           'riscv64-unknown-elf-gcc')
       if shutil.which(self.compiler_path) is None:
           logger.error(self.compiler_path + \
                   ': executable not found. Please check environment setup.')
           raise SystemExit(1)

       # Get objcopy from environment
       self.objcopy_path = os.environ.get('RISCV_OBJCOPY',
           'riscv64-unknown-elf-objcopy')
       if shutil.which(self.objcopy_path) is None:
           logger.error(
               self.objcopy_path + \
               ': executable not found. Please check environment setup.')
           raise SystemExit(1)

       # Note the march is not hardwired here, because it will change for each
       # test. Similarly the output elf name and compile macros will be assigned later in the
       # runTests function
       self.compile_cmd = '{0} -march={1} \
         -DXLEN={2} -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles \
         -T '+self.pluginpath+'/../env/{6}.ld \
         -I '+self.pluginpath+'/../env/ \
         -I ' + archtest_env + ' {3} -o {4} {5}'

       self.objcopy_cmd = '{0} -O binary {1} {2}'

    def build(self, isa_yaml, platform_yaml):
        # load the isa yaml as a dictionary in python.
        ispec = utils.load_yaml(isa_yaml)['hart0']

        # capture the XLEN value by picking the max value in 'supported_xlen' field of isa yaml. This
        # will be useful in setting integer value in the compiler string (if not already hardcoded);
        self.xlen = ('64' if 64 in ispec['supported_xlen'] else '32')

        # for spike start building the '--isa' argument. the self.isa is dutnmae specific and may not be
        # useful for all DUTs
        self.isa = 'rv' + self.xlen
        if 'I' in ispec['ISA']:
            self.isa += 'i'
        if 'M' in ispec['ISA']:
            self.isa += 'm'
        if 'A' in ispec['ISA']:
            self.isa += 'a'
        if 'F' in ispec['ISA']:
            self.isa += 'f'
        if 'D' in ispec['ISA']:
            self.isa += 'd'
        if 'C' in ispec['ISA']:
            self.isa += 'c'
        if 'Zicsr' in ispec['ISA']:
            self.isa += '_zicsr'
        if 'Zifencei' in ispec['ISA']:
            self.isa += '_zifencei'
        if 'Zba' in ispec['ISA']:
            self.isa += '_zba'
        if 'Zbb' in ispec['ISA']:
            self.isa += '_zbb'
        if 'Zbc' in ispec['ISA']:
            self.isa += '_zbc'
        if 'Zbs' in ispec['ISA']:
            self.isa += '_zbs'

        self.compile_cmd = self.compile_cmd + \
            ' -mabi=' + \
            ('lp64 ' if 64 in ispec['supported_xlen'] else 'ilp32 ')

    def runTests(self, testList):
        # Delete Makefile if it already exists.
        if os.path.exists(self.work_dir+ '/Makefile.' + self.name[:-1]):
            os.remove(self.work_dir+ '/Makefile.' + self.name[:-1])

        # create an instance the makeUtil class that we will use to create targets.
        make = utils.makeUtil(
            makefilePath=os.path.join(
                self.work_dir, 'Makefile.' + self.name[:-1]))

        # set the make command that will be used. The num_jobs parameter was set in the __init__
        # function earlier
        make.makeCommand = 'make -k -j' + self.num_jobs

        # we will iterate over each entry in the testList. Each entry node will be refered to by the
        # variable testname.
        for testname in testList:
            # for each testname we get all its fields (as described by the testList format)
            testentry = testList[testname]

            # Get the ISA of the test
            isa = self.isa

            # we capture the path to the assembly file of this test
            test = testentry['test_path']

            # capture the directory where the artifacts of this test will be dumped/created. RISCOF is
            # going to look into this directory for the signature files
            test_dir = testentry['work_dir']

            # name of the elf file after compilation of the test
            elf = 'my.elf'

            # name of the caliptra elf file after compilation of the test
            caliptra_elf = 'my_caliptra.elf'

            # name of the binary file to dump from the elf file
            binary = 'my.bin'

            # name of the signature file as per requirement of RISCOF. RISCOF expects the signature to
            # be named as DUT<dut-name>.signature. The below variable creates an absolute path of
            # signature file.
            sig_file = os.path.join(test_dir, self.name[:-1] + '.signature')

            # for each test there are specific compile macros that need to be enabled. The macros in
            # the testList node only contain the macros/values. For the gcc toolchain we need to
            # prefix with '-D'. The following does precisely that.
            compile_macros= ' -D' + ' -D'.join(testentry['macros'])

            # substitute all variables in the compile command that we created in the initialize
            # function
            compile_cmd = self.compile_cmd.format(
                self.compiler_path,
                isa,
                self.xlen,
                test,
                elf,
                compile_macros,
                'link')

            # XXX - A binary must be built for caliptra, as Spike cannot ingest
            # the ELF file we need for Caliptra
            caliptra_cmd = self.compile_cmd.format(
                self.compiler_path,
                isa,
                self.xlen,
                test,
                caliptra_elf,
                compile_macros,
                'link-caliptra')

            # Create output binary file for tests
            objcmd = self.objcopy_cmd.format(
                self.objcopy_path,
                caliptra_elf,
                binary)

            # Command to run spike
            simcmd = self.dut_exe + \
                ' --isa={0} +signature={1} +signature-granularity=4 {2}'.format(
                    self.isa, sig_file, elf)

            # concatenate all commands that need to be executed within a make-target.
            execute = '@cd {0}; {1}; {2}; {3}; {4};'.format(
                testentry['work_dir'],
                compile_cmd,
                caliptra_cmd,
                objcmd,
                simcmd)

            # create a target. The makeutil will create a target with the name 'TARGET<num>' where num
            # starts from 0 and increments automatically for each new target that is added
            make.add_target(execute)

        # once the make-targets are done and the makefile has been created, run all the targets in
        # parallel using the make command set above.
        make.execute_all(self.work_dir)

        # We don't need to proceed beyond this point, we have what we need
        raise SystemExit(0)
