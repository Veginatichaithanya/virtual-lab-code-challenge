
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Play, Bug, AlertTriangle, AlertCircle, Terminal, Cpu, FileWarning } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';

interface CompilerError {
  stage: 'lexer' | 'parser' | 'ast' | 'semantic' | 'optimizer' | 'generator' | 'runtime' | 'global';
  type: string;
  message: string;
  line?: number;
  column?: number;
  timestamp: string;
}

interface CodeEditorProps {
  code: string;
  onCodeChange: (code: string) => void;
  onRunCode: () => void;
  onRunTests: () => void;
  isRunning: boolean;
  isTesting: boolean;
  output: string;
  errorLogs: any[]; // We'll replace this with our new error structure
  showThumbsUp: boolean;
  showThumbsDown: boolean;
  allTestsPassed: boolean;
}

const CodeEditor: React.FC<CodeEditorProps> = ({
  code,
  onCodeChange,
  onRunCode,
  onRunTests,
  isRunning,
  isTesting,
  output,
  errorLogs,
  showThumbsUp,
  showThumbsDown,
  allTestsPassed
}) => {
  const [activeErrorTab, setActiveErrorTab] = useState<string>('all');

  // Structured compiler errors demonstration
  const compilerErrors: CompilerError[] = errorLogs.map((log, index) => {
    // This is a simulation - in a real app, the backend would provide structured errors
    const stages = ['lexer', 'parser', 'ast', 'semantic', 'optimizer', 'generator', 'runtime', 'global'] as const;
    const randomStage = stages[Math.min(index, stages.length - 1)];
    return {
      stage: randomStage,
      type: log.type || 'Error',
      message: log.message,
      line: typeof log.line === 'number' ? log.line : Math.floor(Math.random() * code.split('\n').length) + 1,
      column: typeof log.column === 'number' ? log.column : Math.floor(Math.random() * 30) + 1,
      timestamp: new Date().toISOString()
    };
  });

  // Get errors for the active tab
  const getFilteredErrors = () => {
    if (activeErrorTab === 'all') return compilerErrors;
    return compilerErrors.filter(error => error.stage === activeErrorTab);
  };
  
  // Error stage icons
  const stageIcons = {
    lexer: <Terminal className="h-4 w-4" />,
    parser: <FileWarning className="h-4 w-4" />,
    ast: <Bug className="h-4 w-4" />,
    semantic: <AlertCircle className="h-4 w-4" />,
    optimizer: <Cpu className="h-4 w-4" />,
    generator: <AlertCircle className="h-4 w-4" />,
    runtime: <AlertTriangle className="h-4 w-4" />,
    global: <Bug className="h-4 w-4" />,
  };

  return (
    <div className="bg-cyber-dark rounded-lg border border-cyber-blue/20 shadow-sm overflow-hidden flex flex-col">
      {/* Code editor header */}
      <div className="bg-cyber-darkblue px-4 py-2 flex items-center justify-between border-b border-cyber-blue/20">
        <span className="text-white font-medium">Python Editor</span>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={onRunCode}
            disabled={isRunning || isTesting}
            className="text-white hover:bg-white/10"
          >
            <Play className="h-4 w-4 mr-1" />
            Run Code
          </Button>
          <Button
            variant="default"
            size="sm"
            onClick={onRunTests}
            disabled={isRunning || isTesting}
            className="bg-cyber-blue hover:bg-cyber-blue/90 text-white"
          >
            Execute Test Cases
          </Button>
        </div>
      </div>
      
      {/* Code editor area */}
      <div className="flex-1 relative">
        <div className="font-mono text-sm w-full h-full bg-cyber-dark text-white overflow-auto">
          <div className="p-4 flex">
            <div className="line-numbers pr-4 text-gray-500 select-none">
              {code.split('\n').map((_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <textarea
              value={code}
              onChange={(e) => onCodeChange(e.target.value)}
              className="flex-1 bg-transparent outline-none resize-none min-h-[300px] font-mono"
              spellCheck="false"
              style={{ minHeight: `${code.split('\n').length * 24}px` }}
            />
          </div>
        </div>
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
      
      {/* Compiler Error Logs with Pipeline Stages */}
      {compilerErrors.length > 0 && (
        <div className="border-t border-cyber-blue/20">
          <div className="bg-cyber-darkblue px-4 py-2 flex items-center justify-between">
            <span className="text-white font-medium">Compiler Pipeline</span>
            <span className="text-red-400 text-sm">{compilerErrors.length} errors</span>
          </div>
          
          <Tabs value={activeErrorTab} onValueChange={setActiveErrorTab} className="w-full">
            <div className="bg-black/40 p-2 border-b border-cyber-blue/10">
              <ScrollArea className="w-full whitespace-nowrap">
                <TabsList className="bg-cyber-dark/50 p-1">
                  <TabsTrigger value="all" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    All Stages ({compilerErrors.length})
                  </TabsTrigger>
                  <TabsTrigger value="lexer" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    Lexer ({compilerErrors.filter(e => e.stage === 'lexer').length})
                  </TabsTrigger>
                  <TabsTrigger value="parser" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    Parser ({compilerErrors.filter(e => e.stage === 'parser').length})
                  </TabsTrigger>
                  <TabsTrigger value="ast" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    AST ({compilerErrors.filter(e => e.stage === 'ast').length})
                  </TabsTrigger>
                  <TabsTrigger value="semantic" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    Semantic ({compilerErrors.filter(e => e.stage === 'semantic').length})
                  </TabsTrigger>
                  <TabsTrigger value="optimizer" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    Optimizer ({compilerErrors.filter(e => e.stage === 'optimizer').length})
                  </TabsTrigger>
                  <TabsTrigger value="generator" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    Generator ({compilerErrors.filter(e => e.stage === 'generator').length})
                  </TabsTrigger>
                  <TabsTrigger value="runtime" className="text-xs data-[state=active]:bg-cyber-blue/20 data-[state=active]:text-white">
                    Runtime ({compilerErrors.filter(e => e.stage === 'runtime').length})
                  </TabsTrigger>
                </TabsList>
              </ScrollArea>
            </div>
            
            <TabsContent value={activeErrorTab} className="m-0">
              <div className="max-h-64 overflow-auto p-4 font-mono text-sm bg-black/40 space-y-3">
                {getFilteredErrors().map((error, i) => (
                  <div key={i} className={`border-l-2 pl-3 py-2 ${
                    error.stage === 'lexer' ? 'border-yellow-500 bg-yellow-500/5' :
                    error.stage === 'parser' ? 'border-orange-500 bg-orange-500/5' :
                    error.stage === 'ast' ? 'border-red-500 bg-red-500/5' :
                    error.stage === 'semantic' ? 'border-purple-500 bg-purple-500/5' :
                    error.stage === 'optimizer' ? 'border-blue-500 bg-blue-500/5' :
                    error.stage === 'generator' ? 'border-green-500 bg-green-500/5' :
                    error.stage === 'runtime' ? 'border-red-600 bg-red-600/5' :
                    'border-gray-500 bg-gray-500/5'
                  }`}>
                    <div className="flex items-center gap-2 text-white/90">
                      <span className="bg-cyber-dark p-1 rounded">
                        {stageIcons[error.stage]}
                      </span>
                      <span className="text-xs uppercase font-bold">
                        {error.stage} Stage
                      </span>
                      <span className="text-xs text-white/60 ml-auto">
                        {new Date(error.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    
                    <div className="mt-2 text-white/80">
                      <span className="text-white font-semibold">{error.type}: </span>
                      {error.message}
                    </div>
                    
                    {(error.line !== undefined && error.column !== undefined) && (
                      <div className="mt-1 text-xs text-white/60">
                        at line {error.line}, column {error.column}
                      </div>
                    )}
                  </div>
                ))}
                
                {getFilteredErrors().length === 0 && (
                  <div className="text-center py-8 text-white/50">
                    No errors in this stage
                  </div>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </div>
      )}
    </div>
  );
};

export default CodeEditor;
