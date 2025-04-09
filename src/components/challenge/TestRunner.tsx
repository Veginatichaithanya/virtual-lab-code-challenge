
import { useState } from 'react';
import { useToast } from '@/hooks/use-toast';

interface TestRunnerProps {
  challengeId: string;
  testCases: Array<{
    input: string;
    expectedOutput: string;
  }>;
  code: string;
  saveUserCode: (challengeId: string, code: string) => void;
  completeChallenge: (challengeId: string) => void;
}

export interface TestRunnerState {
  isRunning: boolean;
  isTesting: boolean;
  output: string;
  errorLogs: { type: string; message: string }[];
  showThumbsUp: boolean;
  showThumbsDown: boolean;
  allTestsPassed: boolean;
}

export const useTestRunner = ({
  challengeId,
  testCases,
  code,
  saveUserCode,
  completeChallenge
}: TestRunnerProps) => {
  const { toast } = useToast();
  const [state, setState] = useState<TestRunnerState>({
    isRunning: false,
    isTesting: false,
    output: '',
    errorLogs: [],
    showThumbsUp: false,
    showThumbsDown: false,
    allTestsPassed: false
  });

  // Simulated code execution
  const runCode = () => {
    setState(prev => ({ ...prev, isRunning: true, output: '', errorLogs: [] }));
    
    // Save the current code
    saveUserCode(challengeId, code);
    
    // Simulate execution delay
    setTimeout(() => {
      // This is a simple simulation
      // In a real app, we would execute the actual Python code
      const simulatedOutput = "Running code...\n> Executing caesar_cipher('hello', 3)\n> Result: 'khoor'";
      setState(prev => ({ ...prev, output: simulatedOutput, isRunning: false }));
    }, 1500);
  };
  
  // Simulated test execution
  const runTests = () => {
    setState(prev => ({ 
      ...prev, 
      isTesting: true, 
      output: '', 
      errorLogs: [],
      showThumbsUp: false,
      showThumbsDown: false 
    }));
    
    // Save the current code
    saveUserCode(challengeId, code);
    
    // Simulate testing delay
    setTimeout(() => {
      // This is a simulation
      // In a real app, we would run the actual tests
      const testResults = [
        { passed: true, input: testCases[0].input, expected: testCases[0].expectedOutput, actual: testCases[0].expectedOutput },
        { passed: true, input: testCases[1].input, expected: testCases[1].expectedOutput, actual: testCases[1].expectedOutput },
      ];
      
      const allPassed = testResults.every(r => r.passed);
      
      let testOutput = "Running tests...\n";
      testResults.forEach((result, i) => {
        testOutput += `\nTest Case ${i + 1}:\n`;
        testOutput += `Input: ${result.input}\n`;
        testOutput += `Expected: ${result.expected}\n`;
        testOutput += `Actual: ${result.actual}\n`;
        testOutput += `Result: ${result.passed ? 'PASSED ✓' : 'FAILED ✗'}\n`;
      });
      
      testOutput += `\n${allPassed ? 'All tests passed! Great job!' : 'Some tests failed. Try again!'}`;
      
      setState(prev => ({
        ...prev,
        output: testOutput,
        isTesting: false,
        showThumbsUp: allPassed,
        allTestsPassed: allPassed,
        showThumbsDown: !allPassed
      }));
      
      if (allPassed) {
        completeChallenge(challengeId);
        
        toast({
          title: "Challenge Completed!",
          description: `You've successfully completed this challenge.`,
        });
      } else {
        // Hide thumbs down after 3 seconds
        setTimeout(() => {
          setState(prev => ({ ...prev, showThumbsDown: false }));
        }, 3000);
      }
    }, 2000);
  };

  return {
    ...state,
    runCode,
    runTests,
    setState
  };
};
