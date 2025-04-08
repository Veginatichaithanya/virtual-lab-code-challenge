
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useUser } from '@/context/UserContext';
import { challenges } from '@/data/challengesData';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';

// Import the new refactored components
import ChallengeHeader from '@/components/challenge/ChallengeHeader';
import ChallengeDescription from '@/components/challenge/ChallengeDescription';
import ChallengeSolution from '@/components/challenge/ChallengeSolution';
import CodeEditor from '@/components/challenge/CodeEditor';

const ChallengePage = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user, completeChallenge, hasCompletedAllChallenges, saveUserCode, getUserCode } = useUser();
  const { toast } = useToast();
  
  const [code, setCode] = useState('');
  const [output, setOutput] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [showThumbsUp, setShowThumbsUp] = useState(false);
  const [showThumbsDown, setShowThumbsDown] = useState(false);
  const [allTestsPassed, setAllTestsPassed] = useState(false);
  const [errorLogs, setErrorLogs] = useState<{ type: string; message: string }[]>([]);
  const [activeTab, setActiveTab] = useState('description');
  
  // Find the current challenge
  const challenge = challenges.find(c => c.id === id);
  
  // Find next challenge for the "Next Challenge" button
  const currentIndex = challenges.findIndex(c => c.id === id);
  const nextChallenge = currentIndex < challenges.length - 1 ? challenges[currentIndex + 1] : null;
  
  // Redirect if challenge not found or user not registered
  useEffect(() => {
    if (!challenge) {
      navigate('/dashboard');
      return;
    }
    
    if (!user.isRegistered) {
      navigate('/');
      return;
    }
    
    // Try to load saved code or use initial code
    const savedCode = getUserCode(challenge.id);
    setCode(savedCode || challenge.initialCode);
    
    // Auto-mark as completed for the purpose of showing all solutions
    if (!user.completedChallenges.includes(challenge.id)) {
      completeChallenge(challenge.id);
      setAllTestsPassed(true);
    } else {
      setAllTestsPassed(true);
    }
  }, [challenge, navigate, user.isRegistered, user.completedChallenges, completeChallenge, id, getUserCode]);
  
  if (!challenge) {
    return null;
  }
  
  // Simulated code execution (in a real app, this would run Python code)
  const runCode = () => {
    setIsRunning(true);
    setOutput('');
    setErrorLogs([]);
    
    // Save the current code
    saveUserCode(challenge.id, code);
    
    // Simulate execution delay
    setTimeout(() => {
      // This is a simple simulation
      // In a real app, we would execute the actual Python code
      const simulatedOutput = "Running code...\n> Executing caesar_cipher('hello', 3)\n> Result: 'khoor'";
      setOutput(simulatedOutput);
      setIsRunning(false);
    }, 1500);
  };
  
  // Simulated test execution
  const runTests = () => {
    setIsTesting(true);
    setOutput('');
    setErrorLogs([]);
    setShowThumbsUp(false);
    setShowThumbsDown(false);
    
    // Save the current code
    saveUserCode(challenge.id, code);
    
    // Simulate testing delay
    setTimeout(() => {
      // This is a simulation
      // In a real app, we would run the actual tests
      const testResults = [
        { passed: true, input: challenge.testCases[0].input, expected: challenge.testCases[0].expectedOutput, actual: challenge.testCases[0].expectedOutput },
        { passed: true, input: challenge.testCases[1].input, expected: challenge.testCases[1].expectedOutput, actual: challenge.testCases[1].expectedOutput },
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
      
      setOutput(testOutput);
      setIsTesting(false);
      
      if (allPassed) {
        setShowThumbsUp(true);
        setAllTestsPassed(true);
        completeChallenge(challenge.id);
        
        toast({
          title: "Challenge Completed!",
          description: `You've successfully completed the ${challenge.title} challenge.`,
        });
      } else {
        setShowThumbsDown(true);
        setTimeout(() => {
          setShowThumbsDown(false);
        }, 3000);
      }
    }, 2000);
  };
  
  const goToNextChallenge = () => {
    if (nextChallenge) {
      navigate(`/challenge/${nextChallenge.id}`);
    } else {
      navigate('/dashboard');
    }
  };

  const handleGenerateCertificate = () => {
    navigate('/certificate');
  };
  
  // Handle code changes in the editor
  const handleCodeChange = (newCode: string) => {
    setCode(newCode);
  };
  
  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Header */}
      <ChallengeHeader 
        title={challenge.title}
        difficulty={challenge.difficulty}
        marks={challenge.marks}
        allTestsPassed={allTestsPassed}
        hasNextChallenge={!!nextChallenge}
        nextChallengeId={nextChallenge?.id || null}
        hasCompletedAllChallenges={hasCompletedAllChallenges()}
        onGenerateCertificate={handleGenerateCertificate}
        onGoToNextChallenge={goToNextChallenge}
      />
      
      {/* Main content */}
      <div className="flex-1 container mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left panel - Challenge description */}
        <div className="bg-card rounded-lg border shadow-sm overflow-hidden">
          <Tabs defaultValue="description" value={activeTab} onValueChange={setActiveTab} className="w-full">
            <div className="border-b px-3">
              <TabsList className="bg-transparent h-12">
                <TabsTrigger value="description" className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-cyber-blue data-[state=active]:text-cyber-blue rounded-none py-3 h-12">
                  Description
                </TabsTrigger>
                <TabsTrigger value="solution" className="data-[state=active]:bg-transparent data-[state=active]:border-b-2 data-[state=active]:border-cyber-blue data-[state=active]:text-cyber-blue rounded-none py-3 h-12">
                  Solution
                </TabsTrigger>
              </TabsList>
            </div>
            
            <TabsContent value="description" className="p-6 space-y-6 m-0">
              <ChallengeDescription 
                title={challenge.title}
                description={challenge.description}
                howItWorks={challenge.howItWorks}
                examples={challenge.examples}
              />
            </TabsContent>
            
            <TabsContent value="solution" className="p-6 m-0">
              <ChallengeSolution 
                challengeId={challenge.id} 
                title={challenge.title} 
                marks={challenge.marks} 
              />
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Right panel - Code editor */}
        <CodeEditor 
          code={code}
          onCodeChange={handleCodeChange}
          onRunCode={runCode}
          onRunTests={runTests}
          isRunning={isRunning}
          isTesting={isTesting}
          output={output}
          errorLogs={errorLogs}
          showThumbsUp={showThumbsUp}
          showThumbsDown={showThumbsDown}
          allTestsPassed={allTestsPassed}
        />
      </div>
    </div>
  );
};

export default ChallengePage;
