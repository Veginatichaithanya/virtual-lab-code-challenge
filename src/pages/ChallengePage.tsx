
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useUser } from '@/context/UserContext';
import { challenges } from '@/data/challengesData';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ChevronLeft, Play, CheckCircle, ThumbsUp, ThumbsDown, CheckCheck, ArrowRight } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';

const ChallengePage = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user, completeChallenge } = useUser();
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
    
    setCode(challenge.initialCode);
  }, [challenge, navigate, user.isRegistered]);
  
  if (!challenge) {
    return null;
  }
  
  // Simulated code execution (in a real app, this would run Python code)
  const runCode = () => {
    setIsRunning(true);
    setOutput('');
    setErrorLogs([]);
    
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
  
  // Find next challenge for the "Next Challenge" button
  const currentIndex = challenges.findIndex(c => c.id === id);
  const nextChallenge = currentIndex < challenges.length - 1 ? challenges[currentIndex + 1] : null;
  
  const goToNextChallenge = () => {
    if (nextChallenge) {
      navigate(`/challenge/${nextChallenge.id}`);
    } else {
      navigate('/dashboard');
    }
  };
  
  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={() => navigate('/dashboard')}
              className="font-medium"
            >
              <ChevronLeft className="h-4 w-4 mr-1" />
              Back to Dashboard
            </Button>
            <Separator orientation="vertical" className="h-6" />
            <h1 className="text-xl font-bold">{challenge.title}</h1>
            <div className="hidden md:flex gap-2 ml-2">
              <Badge variant="outline" className={`${
                challenge.difficulty === 'Easy' ? 'bg-green-100/50 text-green-700 border-green-200' : 
                challenge.difficulty === 'Medium' ? 'bg-yellow-100/50 text-yellow-700 border-yellow-200' : 
                'bg-red-100/50 text-red-700 border-red-200'
              }`}>
                {challenge.difficulty}
              </Badge>
              <Badge variant="outline" className="bg-purple-100/50 text-purple-700 border-purple-200">
                {challenge.marks} Marks
              </Badge>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            {allTestsPassed && (
              <Badge variant="default" className="bg-green-500 text-white gap-1">
                <CheckCheck className="h-3.5 w-3.5 mr-1" />
                Completed
              </Badge>
            )}
            {allTestsPassed && nextChallenge && (
              <Button 
                variant="default"
                size="sm"
                onClick={goToNextChallenge}
                className="bg-cyber-accent hover:bg-cyber-accent/90"
              >
                Next Challenge
                <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            )}
          </div>
        </div>
      </header>
      
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
              <div>
                <h2 className="text-xl font-bold mb-2">{challenge.title}</h2>
                <p className="text-muted-foreground">{challenge.description}</p>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold mb-2">How It Works</h3>
                <ul className="list-disc pl-5 space-y-1">
                  {challenge.howItWorks.map((step, i) => (
                    <li key={i} className="text-muted-foreground">{step}</li>
                  ))}
                </ul>
              </div>
              
              <div>
                <h3 className="text-lg font-semibold mb-2">Example Inputs and Outputs</h3>
                <div className="space-y-3">
                  {challenge.examples.map((example, i) => (
                    <div key={i} className="bg-muted/50 rounded-lg p-3">
                      <div className="font-mono text-sm"><span className="text-cyber-blue">Input:</span> {example.input}</div>
                      <div className="font-mono text-sm"><span className="text-green-600">Output:</span> {example.output}</div>
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="solution" className="p-6 m-0">
              <div className="bg-muted/50 rounded-lg p-4">
                <p className="mb-4 text-muted-foreground">This tab will show the solution after you've successfully completed the challenge or if you've requested to see it.</p>
                
                {user.completedChallenges.includes(challenge.id) ? (
                  <div className="bg-cyber-dark rounded-lg p-4 font-mono text-sm text-white overflow-auto">
                    {/* Solution code would be displayed here */}
                    <pre className="whitespace-pre-wrap">
                      {`def caesar_cipher(plaintext, shift):
    result = ""
    # Iterate through each character in the plaintext
    for char in plaintext:
        # Check if the character is an alphabet
        if char.isalpha():
            # Determine the ASCII offset based on case
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Shift the character and handle wrapping
            shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
            result += chr(shifted)
        else:
            # Keep non-alphabetic characters as they are
            result += char
    return result`}
                    </pre>
                  </div>
                ) : (
                  <Button
                    variant="outline"
                    className="w-full border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/10"
                  >
                    Reveal Solution (Marks will not be awarded)
                  </Button>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </div>
        
        {/* Right panel - Code editor */}
        <div className="bg-cyber-dark rounded-lg border border-cyber-blue/20 shadow-sm overflow-hidden flex flex-col">
          {/* Code editor header */}
          <div className="bg-cyber-darkblue px-4 py-2 flex items-center justify-between border-b border-cyber-blue/20">
            <span className="text-white font-medium">Python Editor</span>
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={runCode}
                disabled={isRunning || isTesting}
                className="text-white hover:bg-white/10"
              >
                <Play className="h-4 w-4 mr-1" />
                Run Code
              </Button>
              <Button
                variant="default"
                size="sm"
                onClick={runTests}
                disabled={isRunning || isTesting || allTestsPassed}
                className={`${
                  allTestsPassed 
                    ? 'bg-green-600 hover:bg-green-700' 
                    : 'bg-cyber-blue hover:bg-cyber-blue/90'
                } text-white`}
              >
                {allTestsPassed ? (
                  <>
                    <CheckCircle className="h-4 w-4 mr-1" />
                    Successfully Executed
                  </>
                ) : (
                  'Execute Test Cases'
                )}
              </Button>
            </div>
          </div>
          
          {/* Code editor area */}
          <div className="flex-1 relative">
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="font-mono text-sm w-full h-full p-4 bg-cyber-dark text-white resize-none focus:outline-none code-editor"
              spellCheck="false"
            />
            
            {/* Feedback animations */}
            {showThumbsUp && (
              <div className="absolute top-4 right-4 bg-green-500/10 p-2 rounded-full">
                <ThumbsUp className="h-8 w-8 text-green-500 animate-thumbs-up" />
              </div>
            )}
            
            {showThumbsDown && (
              <div className="absolute top-4 right-4 bg-red-500/10 p-2 rounded-full">
                <ThumbsDown className="h-8 w-8 text-red-500 animate-thumbs-down" />
              </div>
            )}
          </div>
          
          {/* Output and logs area */}
          <div className="border-t border-cyber-blue/20">
            <div className="bg-cyber-darkblue px-4 py-2 flex items-center justify-between">
              <span className="text-white font-medium">Output</span>
              {(isRunning || isTesting) && (
                <span className="text-cyber-lightblue text-sm">Processing...</span>
              )}
            </div>
            <div className="h-48 overflow-auto p-4 font-mono text-sm text-white bg-black/30">
              {output || "Run your code to see output here..."}
            </div>
          </div>
          
          {/* Error logs */}
          {errorLogs.length > 0 && (
            <div className="border-t border-cyber-blue/20">
              <div className="bg-cyber-darkblue px-4 py-2 flex items-center justify-between">
                <span className="text-white font-medium">Error Logs</span>
                <span className="text-red-400 text-sm">{errorLogs.length} errors</span>
              </div>
              <div className="max-h-48 overflow-auto p-4 font-mono text-sm text-red-400 bg-black/30 space-y-2">
                {errorLogs.map((log, i) => (
                  <div key={i} className="border-l-2 border-red-500 pl-2">
                    <span className="text-red-300 font-semibold">{log.type}: </span>
                    {log.message}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ChallengePage;
