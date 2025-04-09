
import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useUser } from '@/context/UserContext';
import { challenges } from '@/data/challengesData';

// Import the refactored components
import ChallengeHeader from '@/components/challenge/ChallengeHeader';
import ChallengeContent from '@/components/challenge/ChallengeContent';
import { useTestRunner } from '@/components/challenge/TestRunner';

const ChallengePage = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user, completeChallenge, hasCompletedAllChallenges, saveUserCode, getUserCode } = useUser();
  
  const [code, setCode] = useState('');
  const [activeTab, setActiveTab] = useState('description');
  
  // Find the current challenge
  const challenge = challenges.find(c => c.id === id);
  
  // Find next challenge for the "Next Challenge" button
  const currentIndex = challenges.findIndex(c => c.id === id);
  const nextChallenge = currentIndex < challenges.length - 1 ? challenges[currentIndex + 1] : null;
  
  // Initialize test runner
  const testRunner = useTestRunner({
    challengeId: challenge?.id || '',
    testCases: challenge?.testCases || [],
    code,
    saveUserCode,
    completeChallenge
  });
  
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
      testRunner.setState(prev => ({ ...prev, allTestsPassed: true }));
    } else {
      testRunner.setState(prev => ({ ...prev, allTestsPassed: true }));
    }
  }, [challenge, navigate, user.isRegistered, user.completedChallenges, completeChallenge, id, getUserCode, testRunner]);
  
  if (!challenge) {
    return null;
  }
  
  // Handle code changes in the editor
  const handleCodeChange = (newCode: string) => {
    setCode(newCode);
  };
  
  const handleGenerateCertificate = () => {
    navigate('/certificate');
  };
  
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
      <ChallengeHeader 
        title={challenge.title}
        difficulty={challenge.difficulty}
        marks={challenge.marks}
        allTestsPassed={testRunner.allTestsPassed}
        hasNextChallenge={!!nextChallenge}
        nextChallengeId={nextChallenge?.id || null}
        hasCompletedAllChallenges={hasCompletedAllChallenges()}
        onGenerateCertificate={handleGenerateCertificate}
        onGoToNextChallenge={goToNextChallenge}
      />
      
      {/* Main content */}
      <ChallengeContent 
        challenge={challenge}
        code={code}
        onCodeChange={handleCodeChange}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        testRunnerState={testRunner}
        runCode={testRunner.runCode}
        runTests={testRunner.runTests}
      />
    </div>
  );
};

export default ChallengePage;
