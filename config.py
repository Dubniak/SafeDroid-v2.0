"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""


class Config:
    def __init__(self, cname):
        self.c = {}
        with open(cname, 'r') as f:
            for line in f:
                if line[0].isupper() or line[0] == '\n':
                    continue
                ff = line.split(':')
                values = []
                s = ff[1].replace(" ", "")

                # multiple values for a category
                if s[0] == '[':
                    s = s.replace("[", "")
                    s = s.replace("]", "")
                    s = s.replace("\n", "")
                    s = s.replace("\t", "")
                    for v in s.split(','):
                        try:
                            values.append(float(v))
                        except Exception:
                            values.append(v)
                    self.c[''.join(ff[0].split())] = values

                else:
                    self.c[''.join(ff[0].split())] = ''.join(ff[1].split())

    def reduce_size(self):
        return self.c['sample_reduce_size']

    def malicious_size(self):
        return self.c['malicious_size']

    def threshold(self):
        return self.c['threshold']

    def cv(self):
        return int(self.c['cv'][0])

    def test_size(self):
        return self.c['test_size'][0]

    def display_plots(self):
        return self.c['display_plots'][0] == 1

    def plot_to_file(self):
        return self.c['plot_to_file'][0] == 1

    def classifier(self):
        return self.c['classifier']

    def neighbors(self):
        return map(int, self.c['neighbors'])

    def radius(self):
        return self.c['radius']
