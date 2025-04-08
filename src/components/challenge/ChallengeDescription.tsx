
import React from 'react';

interface Example {
  input: string;
  output: string;
}

interface ChallengeDescriptionProps {
  title: string;
  description: string;
  howItWorks: string[];
  examples: Example[];
}

const ChallengeDescription: React.FC<ChallengeDescriptionProps> = ({
  title,
  description,
  howItWorks,
  examples
}) => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold mb-2">{title}</h2>
        <p className="text-muted-foreground">{description}</p>
      </div>
      
      <div>
        <h3 className="text-lg font-semibold mb-2">How It Works</h3>
        <ul className="list-disc pl-5 space-y-1">
          {howItWorks.map((step, i) => (
            <li key={i} className="text-muted-foreground">{step}</li>
          ))}
        </ul>
      </div>
      
      <div>
        <h3 className="text-lg font-semibold mb-2">Example Inputs and Outputs</h3>
        <div className="space-y-3">
          {examples.map((example, i) => (
            <div key={i} className="bg-muted/50 rounded-lg p-3">
              <div className="font-mono text-sm"><span className="text-cyber-blue">Input:</span> {example.input}</div>
              <div className="font-mono text-sm"><span className="text-green-600">Output:</span> {example.output}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ChallengeDescription;
