import os, subprocess, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
import gen_sample_pcap, pcap_analyzer

class TestAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(os.path.dirname(__file__), 'sample_test.pcap')
        gen_sample_pcap.main(cls.path, 10)

    def test_pairs_and_split(self):
        rows = pcap_analyzer.analyze(self.path)
        self.assertEqual(len(rows), 10)
        self.assertEqual([r['id'] for r in rows], list(range(1, 11)))
        for r in rows:  # synthetic ground truth: 85us total = 40 queue + 15 server + 30 return
            self.assertAlmostEqual(r['total_us'], 85, delta=2)
            self.assertAlmostEqual(r['queueing_us'], 40, delta=2)
            self.assertAlmostEqual(r['server_us'], 15, delta=2)
            self.assertAlmostEqual(r['wire_kernel_return_us'], 30, delta=2)

    def test_bad_magic(self):
        bad = self.path + '.bad'; open(bad, 'wb').write(b'nope' + b'\0' * 32)
        with self.assertRaises(ValueError): pcap_analyzer.analyze(bad)

if __name__ == '__main__':
    unittest.main()
