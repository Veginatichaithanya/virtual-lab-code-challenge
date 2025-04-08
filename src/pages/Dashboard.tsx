
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '@/context/UserContext';
import ChallengeCard from '@/components/ChallengeCard';
import { challenges } from '@/data/challengesData';
import { Button } from '@/components/ui/button';
import { Shield, Award, LogOut } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';

const Dashboard = () => {
  const { user, hasCompletedAllChallenges, resetProgress } = useUser();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [showConfetti, setShowConfetti] = useState(false);

  // Redirect to registration if not registered
  useEffect(() => {
    if (!user.isRegistered) {
      navigate('/');
    }
  }, [user.isRegistered, navigate]);

  const handleLogout = () => {
    // Clear user data from localStorage
    localStorage.removeItem('cyber-quest-user');
    // Reload the page to reset all state
    window.location.reload();
  };

  const handleResetProgress = () => {
    resetProgress();
    toast({
      title: "Progress Reset",
      description: "All your challenge progress has been reset.",
    });
  };

  const handleGenerateCertificate = () => {
    // In a real app, we would generate a certificate using user data
    navigate('/certificate');
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <header className="flex flex-col md:flex-row justify-between items-center mb-8 gap-4">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-cyber-blue" />
          <h1 className="text-3xl font-bold tracking-tight">Cyber Code Quest</h1>
        </div>
        <div className="flex flex-col md:flex-row items-center gap-4">
          <div className="bg-card p-3 rounded-lg shadow-sm">
            <p className="text-sm font-medium">Welcome, <span className="text-cyber-blue">{user.fullName}</span></p>
            <p className="text-xs text-muted-foreground">Reg. No: {user.registerNumber}</p>
          </div>
          {hasCompletedAllChallenges() && (
            <Button 
              variant="default" 
              size="sm"
              className="bg-cyber-accent hover:bg-cyber-accent/90"
              onClick={handleGenerateCertificate}
            >
              <Award className="h-4 w-4 mr-2" />
              Generate Certificate
            </Button>
          )}
          <Button 
            variant="outline" 
            size="sm"
            className="border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700"
            onClick={handleLogout}
          >
            <LogOut className="h-4 w-4 mr-2" />
            Log Out
          </Button>
        </div>
      </header>
      
      <div className="bg-gradient-to-r from-cyber-blue/10 to-cyber-accent/10 rounded-lg p-6 mb-8 shadow-sm">
        <div className="flex flex-col md:flex-row justify-between items-center gap-4">
          <div>
            <h2 className="text-xl font-semibold mb-2">Your Cybersecurity Journey</h2>
            <p className="text-muted-foreground">
              Complete all 14 challenges to earn your Cybersecurity Certificate
            </p>
          </div>
          <div className="flex gap-4">
            <Button 
              variant="outline" 
              size="sm"
              className="border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/10"
              onClick={handleResetProgress}
            >
              Reset Progress
            </Button>
            <Button 
              variant="default" 
              size="sm"
              className="bg-cyber-accent hover:bg-cyber-accent/90"
              onClick={handleGenerateCertificate}
              disabled={!hasCompletedAllChallenges()}
            >
              <Award className="h-4 w-4 mr-2" />
              {hasCompletedAllChallenges() ? "Generate Certificate" : "Complete All Challenges"}
            </Button>
          </div>
        </div>
        
        <div className="mt-4 bg-white/50 dark:bg-gray-800/30 h-3 rounded-full overflow-hidden">
          <div 
            className="h-full bg-cyber-blue transition-all duration-500" 
            style={{ 
              width: `${(user.completedChallenges.length / challenges.length) * 100}%` 
            }}
          />
        </div>
        <div className="flex justify-between mt-1 text-xs text-muted-foreground">
          <span>{user.completedChallenges.length} of {challenges.length} complete</span>
          <span>{Math.round((user.completedChallenges.length / challenges.length) * 100)}%</span>
        </div>
      </div>

      <h3 className="text-xl font-semibold mb-4">Cybersecurity Challenges</h3>
      
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {challenges.map((challenge, index) => {
          // All challenges are unlocked
          const isLocked = false;
          
          return (
            <ChallengeCard
              key={challenge.id}
              id={challenge.id}
              title={challenge.title}
              description={challenge.shortDescription}
              difficulty={challenge.difficulty}
              marks={challenge.marks}
              completed={user.completedChallenges.includes(challenge.id)}
              locked={isLocked}
            />
          );
        })}
      </div>
    </div>
  );
};

export default Dashboard;
