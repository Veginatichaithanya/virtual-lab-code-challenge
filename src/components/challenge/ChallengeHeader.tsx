
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { ChevronLeft, Award, ArrowRight } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface ChallengeHeaderProps {
  title: string;
  difficulty: string;
  marks: number;
  allTestsPassed: boolean;
  hasNextChallenge: boolean;
  nextChallengeId: string | null;
  hasCompletedAllChallenges: boolean;
  onGenerateCertificate: () => void;
  onGoToNextChallenge: () => void;
}

const ChallengeHeader: React.FC<ChallengeHeaderProps> = ({
  title,
  difficulty,
  marks,
  allTestsPassed,
  hasNextChallenge,
  nextChallengeId,
  hasCompletedAllChallenges,
  onGenerateCertificate,
  onGoToNextChallenge
}) => {
  const navigate = useNavigate();

  return (
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
          <h1 className="text-xl font-bold">{title}</h1>
          <div className="hidden md:flex gap-2 ml-2">
            <Badge variant="outline" className={`${
              difficulty === 'Easy' ? 'bg-green-100/50 text-green-700 border-green-200' : 
              difficulty === 'Medium' ? 'bg-yellow-100/50 text-yellow-700 border-yellow-200' : 
              'bg-red-100/50 text-red-700 border-red-200'
            }`}>
              {difficulty}
            </Badge>
            <Badge variant="outline" className="bg-purple-100/50 text-purple-700 border-purple-200">
              {marks} Marks
            </Badge>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          {hasCompletedAllChallenges && (
            <Button 
              variant="default"
              size="sm"
              onClick={onGenerateCertificate}
              className="bg-cyber-accent hover:bg-cyber-accent/90"
            >
              <Award className="h-4 w-4 mr-1" />
              Generate Certificate
            </Button>
          )}
          {allTestsPassed && hasNextChallenge && nextChallengeId && (
            <Button 
              variant="default"
              size="sm"
              onClick={onGoToNextChallenge}
              className="bg-cyber-accent hover:bg-cyber-accent/90"
            >
              Next Challenge
              <ArrowRight className="h-4 w-4 ml-1" />
            </Button>
          )}
        </div>
      </div>
    </header>
  );
};

export default ChallengeHeader;
