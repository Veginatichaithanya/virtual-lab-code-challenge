
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Play, CheckCircle, ThumbsUp, ThumbsDown, Check } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface ErrorLog {
  type: string;
  message: string;
}

interface CodeEditorProps {
  code: string;
  onCodeChange: (code: string) => void;
  onRunCode: () => void;
  onRunTests: () => void;
  isRunning: boolean;
  isTesting: boolean;
  output: string;
  errorLogs: ErrorLog[];
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
          <div className="flex items-center gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={onRunTests}
              disabled={isRunning || isTesting}
              className={`${
                allTestsPassed 
                  ? 'bg-cyber-blue hover:bg-cyber-blue/90' 
                  : 'bg-cyber-blue hover:bg-cyber-blue/90'
              } text-white`}
            >
              Execute Test Cases
            </Button>
            
            {allTestsPassed && (
              <Badge variant="default" className="bg-green-500 text-white gap-1">
                <Check className="h-3.5 w-3.5 mr-1" />
                Completed
              </Badge>
            )}
          </div>
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
  );
};

export default CodeEditor;
