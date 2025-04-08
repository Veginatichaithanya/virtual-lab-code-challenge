
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle2, Lock } from "lucide-react";
import { useUser } from "@/context/UserContext";
import { useNavigate } from "react-router-dom";

interface ChallengeCardProps {
  id: string;
  title: string;
  description: string;
  difficulty: 'Easy' | 'Medium' | 'Hard';
  marks: number;
  completed: boolean;
  locked: boolean;
}

const ChallengeCard = ({ id, title, description, difficulty, marks, completed, locked }: ChallengeCardProps) => {
  const navigate = useNavigate();
  const { user } = useUser();

  const handleStartChallenge = () => {
    navigate(`/challenge/${id}`);
  };

  return (
    <Card className={`overflow-hidden transition-all duration-300 hover:shadow-md ${completed ? 'border-green-500/30 bg-green-50/10' : locked ? 'opacity-70 bg-gray-100/5' : 'border-cyber-blue/30 hover:border-cyber-blue/60'}`}>
      <div className={`h-2 ${difficulty === 'Easy' ? 'bg-green-500' : difficulty === 'Medium' ? 'bg-yellow-500' : 'bg-red-500'}`} />
      <CardHeader className="relative pb-2">
        <div className="flex justify-between items-start">
          <CardTitle className="text-lg font-bold">{title}</CardTitle>
          {completed && (
            <CheckCircle2 className="h-5 w-5 text-green-500" />
          )}
          {locked && (
            <Lock className="h-5 w-5 text-gray-400" />
          )}
        </div>
        <div className="flex gap-2 mt-1">
          <Badge variant="outline" className={`text-xs font-medium ${
            difficulty === 'Easy' ? 'bg-green-100/50 text-green-700 border-green-200' : 
            difficulty === 'Medium' ? 'bg-yellow-100/50 text-yellow-700 border-yellow-200' : 
            'bg-red-100/50 text-red-700 border-red-200'
          }`}>
            {difficulty}
          </Badge>
          <Badge variant="outline" className="bg-purple-100/50 text-purple-700 border-purple-200 text-xs font-medium">
            {marks} Marks
          </Badge>
        </div>
        <CardDescription className="line-clamp-2 mt-2 text-sm text-gray-500">
          {description}
        </CardDescription>
      </CardHeader>
      <CardContent className="pb-2">
        <div className="h-1 w-full bg-gray-100 rounded-full overflow-hidden">
          <div className={`h-1 ${completed ? 'bg-green-500' : 'bg-cyber-blue'}`} style={{ width: completed ? '100%' : '0%' }} />
        </div>
      </CardContent>
      <CardFooter>
        <Button 
          onClick={handleStartChallenge} 
          disabled={locked}
          variant={completed ? "outline" : "default"}
          className={`w-full ${completed ? 'text-green-600 border-green-200 hover:bg-green-50' : 'bg-cyber-blue hover:bg-cyber-blue/90 text-white'}`}
        >
          {completed ? "View Completed" : locked ? "Locked" : "Start Challenge"}
        </Button>
      </CardFooter>
    </Card>
  );
};

export default ChallengeCard;
