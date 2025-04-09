
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import ChallengeDescription from '@/components/challenge/ChallengeDescription';
import { ChallengeSolution } from '@/components/challenge/ChallengeSolution';
import CodeEditor from '@/components/challenge/CodeEditor';
import { TestRunnerState } from './TestRunner';

interface ChallengeContentProps {
  challenge: {
    id: string;
    title: string;
    description: string;
    howItWorks: string[];
    examples: { input: string; output: string }[];
  };
  code: string;
  onCodeChange: (code: string) => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  testRunnerState: TestRunnerState;
  runCode: () => void;
  runTests: () => void;
}

const ChallengeContent: React.FC<ChallengeContentProps> = ({
  challenge,
  code,
  onCodeChange,
  activeTab,
  setActiveTab,
  testRunnerState,
  runCode,
  runTests
}) => {
  const { 
    isRunning, 
    isTesting, 
    output, 
    errorLogs, 
    showThumbsUp, 
    showThumbsDown, 
    allTestsPassed 
  } = testRunnerState;

  return (
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
              marks={0} 
            />
          </TabsContent>
        </Tabs>
      </div>
      
      {/* Right panel - Code editor */}
      <CodeEditor 
        code={code}
        onCodeChange={onCodeChange}
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
  );
};

export default ChallengeContent;
